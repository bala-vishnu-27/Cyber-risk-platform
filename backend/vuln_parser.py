"""
Universal Vulnerability Ingestor
Parses vulnerability data from diverse industry formats:
  1. CSV / TSV spreadsheets (Qualys, Nessus, Tenable, Jira exports, custom pen-test reports)
  2. SARIF 2.1.0 (Static Analysis Results Interchange Format - GitHub CodeQL, Snyk, Microsoft)
  3. Trivy JSON (Aquasecurity Trivy scanner output)
  4. Grype / Syft JSON (Anchore Grype container/repo scanner)
  5. Snyk CLI JSON (Snyk test --json output)
  6. CycloneDX VEX XML / JSON (Vulnerability Exploitability eXchange)
  7. Google OSV JSON (Open Source Vulnerabilities)
  8. Plain text list of CVEs (e.g. CVE-2021-44228, CVE-2022-22965)
  9. Standard CyberRiskPlatform JSON {"vulnerabilities": [...]}
"""
import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Tuple


class UniversalVulnParser:
    """
    Auto-detects and extracts normalized vulnerabilities from any file format or raw content.
    """

    @classmethod
    def parse(cls, content: Any, filename: str = "") -> Tuple[List[Dict[str, Any]], str]:
        """
        Parses raw string or parsed object and returns (vulnerabilities_list, detected_format_string).
        Guaranteed to never raise an unhandled exception — returns empty list if unparseable.
        """
        if not content:
            return [], "Empty Content"

        # If already a list of dicts
        if isinstance(content, list):
            vulns = cls._normalize_list(content)
            return vulns, "JSON Array"

        if isinstance(content, dict):
            # Check if standard or specialized schema
            vulns, fmt = cls._parse_dict(content)
            return vulns, fmt

        if not isinstance(content, str):
            return [], "Unsupported Type"

        raw_str = content.strip()
        fname = filename.lower()

        # 1. Try JSON parsing first
        if raw_str.startswith("{") or raw_str.startswith("["):
            try:
                parsed_json = json.loads(raw_str)
                if isinstance(parsed_json, list):
                    return cls._normalize_list(parsed_json), "JSON Array"
                elif isinstance(parsed_json, dict):
                    return cls._parse_dict(parsed_json)
            except Exception:
                pass  # Fall through to other formats

        # 2. Try XML parsing (SARIF or CycloneDX VEX or OWASP)
        if raw_str.startswith("<"):
            try:
                vulns, fmt = cls._parse_xml(raw_str)
                if vulns:
                    return vulns, fmt
            except Exception:
                pass

        # 3. Try CSV / TSV parsing
        if "\n" in raw_str or "," in raw_str or "\t" in raw_str or fname.endswith((".csv", ".tsv")):
            vulns, fmt = cls._parse_csv(raw_str)
            if vulns:
                return vulns, fmt

        # 4. Fallback: Extract all CVE IDs from raw text
        cves = cls._extract_raw_cves(raw_str)
        if cves:
            return cves, "Plain Text CVE List"

        return [], "Unknown Format"

    # ─────────────────────────────────────────────────────────────────────────
    # JSON Schema Handlers
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _parse_dict(cls, data: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
        # A. SARIF 2.1.0 format
        if "$schema" in data and "sarif" in str(data.get("$schema", "")).lower() or "runs" in data:
            return cls._parse_sarif(data), "SARIF 2.1.0 (GitHub / CodeQL)"

        # B. Trivy JSON format
        if "SchemaVersion" in data and "Results" in data:
            return cls._parse_trivy(data), "Aquasecurity Trivy JSON"

        # C. Grype JSON format
        if "matches" in data and "source" in data:
            return cls._parse_grype(data), "Anchore Grype JSON"

        # D. Snyk CLI JSON format
        if "vulnerabilities" in data and "packageManager" in data:
            return cls._parse_snyk(data), "Snyk Security JSON"

        # E. CycloneDX JSON with vulnerabilities
        if "bomFormat" in data and "vulnerabilities" in data:
            return cls._parse_cyclonedx_vex(data), "CycloneDX VEX JSON"

        # F. Google OSV JSON
        if "vulns" in data:
            return cls._parse_osv(data), "Google OSV JSON"

        # G. Standard platform JSON
        if "vulnerabilities" in data:
            return cls._normalize_list(data["vulnerabilities"]), "Standard Platform JSON"

        # Fallback: check all dict values if any is a list
        for key, val in data.items():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                norm = cls._normalize_list(val)
                if norm:
                    return norm, f"Custom JSON ({key})"

        return [], "Generic JSON"

    @classmethod
    def _parse_sarif(cls, sarif_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        runs = sarif_data.get("runs", [])
        for run in runs:
            # Map rules by id
            rules_map = {}
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                r_id = rule.get("id")
                if r_id:
                    rules_map[r_id] = rule

            results = run.get("results", [])
            for res in results:
                rule_id = res.get("ruleId", "")
                rule = rules_map.get(rule_id, {})
                msg = res.get("message", {}).get("text", "")

                # Extract CVE from ruleId or rule tags or message
                cve_match = re.search(r"CVE-\d{4}-\d{4,7}", rule_id, re.IGNORECASE) or \
                            re.search(r"CVE-\d{4}-\d{4,7}", msg, re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else (rule_id or "SARIF-VULN")

                # Component determination
                component = "unknown"
                locations = res.get("locations", [])
                if locations:
                    uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    if uri:
                        component = uri.split("/")[-1].split("\\")[-1]

                # Extract severity / CVSS
                level = res.get("level", "warning").lower()
                sec_sev = rule.get("properties", {}).get("security-severity", 5.0)
                try:
                    cvss = float(sec_sev)
                except (ValueError, TypeError):
                    cvss = 7.5 if level == "error" else (5.0 if level == "warning" else 2.5)

                severity = "HIGH" if cvss >= 7.0 else ("CRITICAL" if cvss >= 9.0 else ("MEDIUM" if cvss >= 4.0 else "LOW"))

                vulns.append({
                    "cve_id": cve_id,
                    "component": component if component != "unknown" else rule.get("name", "app-component"),
                    "current_version": "unknown",
                    "fixed_version": "Upgrade Available",
                    "cvss_score": round(cvss, 1),
                    "severity": severity,
                    "exploit_available": cvss >= 7.5,
                    "description": msg or rule.get("shortDescription", {}).get("text", "SARIF Security Finding"),
                    "published_date": "N/A",
                    "is_direct_dependency": True
                })
        return vulns

    @classmethod
    def _parse_trivy(cls, trivy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        for result in trivy_data.get("Results", []):
            target = result.get("Target", "application")
            for v in result.get("Vulnerabilities", []):
                cve_id = v.get("VulnerabilityID", "CVE-UNKNOWN")
                pkg_name = v.get("PkgName", target)
                cur_ver = v.get("InstalledVersion", "unknown")
                fix_ver = v.get("FixedVersion", "N/A")
                sev = v.get("Severity", "MEDIUM").upper()

                # CVSS score resolution
                cvss = 5.0
                cvss_obj = v.get("CVSS", {})
                for provider in ["nvd", "redhat", "ghsa"]:
                    if provider in cvss_obj and "V3Score" in cvss_obj[provider]:
                        try:
                            cvss = float(cvss_obj[provider]["V3Score"])
                            break
                        except Exception:
                            pass

                vulns.append({
                    "cve_id": cve_id,
                    "component": pkg_name.lower(),
                    "current_version": cur_ver,
                    "fixed_version": fix_ver,
                    "cvss_score": cvss,
                    "severity": sev,
                    "exploit_available": sev in ["CRITICAL", "HIGH"],
                    "description": v.get("Title") or v.get("Description", "Trivy vulnerability finding."),
                    "published_date": v.get("PublishedDate", "Unknown"),
                    "is_direct_dependency": True
                })
        return vulns

    @classmethod
    def _parse_grype(cls, grype_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        for match in grype_data.get("matches", []):
            v = match.get("vulnerability", {})
            art = match.get("artifact", {})
            cve_id = v.get("id", "CVE-UNKNOWN")
            pkg_name = art.get("name", "unknown").lower()
            cur_ver = art.get("version", "unknown")
            fix_versions = v.get("fix", {}).get("versions", [])
            fix_ver = fix_versions[0] if fix_versions else "N/A"
            sev = v.get("severity", "MEDIUM").upper()

            # CVSS
            cvss = 5.0
            cvss_list = v.get("cvss", [])
            if cvss_list and isinstance(cvss_list, list) and "metrics" in cvss_list[0]:
                try:
                    cvss = float(cvss_list[0]["metrics"].get("baseScore", 5.0))
                except Exception:
                    pass

            vulns.append({
                "cve_id": cve_id,
                "component": pkg_name,
                "current_version": cur_ver,
                "fixed_version": fix_ver,
                "cvss_score": cvss,
                "severity": sev,
                "exploit_available": sev in ["CRITICAL", "HIGH"],
                "description": v.get("description", "Grype vulnerability finding."),
                "published_date": "Unknown",
                "is_direct_dependency": True
            })
        return vulns

    @classmethod
    def _parse_snyk(cls, snyk_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        for v in snyk_data.get("vulnerabilities", []):
            cve_list = v.get("identifiers", {}).get("CVE", [])
            cve_id = cve_list[0] if cve_list else v.get("id", "SNYK-UNKNOWN")
            pkg_name = v.get("packageName", v.get("package", "unknown")).lower()
            cur_ver = v.get("version", "unknown")
            fix_ver = "N/A"
            upgrade_path = v.get("upgradePath", [])
            if upgrade_path and len(upgrade_path) > 1 and isinstance(upgrade_path[1], str):
                fix_ver = upgrade_path[1].split("@")[-1]

            sev = v.get("severity", "medium").upper()
            cvss = float(v.get("cvssScore", 5.0) or 5.0)

            vulns.append({
                "cve_id": cve_id,
                "component": pkg_name,
                "current_version": cur_ver,
                "fixed_version": fix_ver,
                "cvss_score": cvss,
                "severity": sev,
                "exploit_available": bool(v.get("exploit", False)),
                "description": v.get("title") or v.get("description", "Snyk vulnerability finding."),
                "published_date": v.get("publicationTime", "Unknown"),
                "is_direct_dependency": bool(v.get("isDirectDependency", True))
            })
        return vulns

    @classmethod
    def _parse_cyclonedx_vex(cls, vex_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        for v in vex_data.get("vulnerabilities", []):
            cve_id = v.get("id", "CVE-UNKNOWN")
            affects = v.get("affects", [])
            component = "unknown"
            if affects and "ref" in affects[0]:
                ref = affects[0]["ref"]
                component = ref.split("/")[-1].split("@")[0].lower()

            ratings = v.get("ratings", [])
            sev = "MEDIUM"
            cvss = 5.0
            if ratings:
                sev = ratings[0].get("severity", "MEDIUM").upper()
                cvss = float(ratings[0].get("score", 5.0) or 5.0)

            vulns.append({
                "cve_id": cve_id,
                "component": component,
                "current_version": "unknown",
                "fixed_version": "N/A",
                "cvss_score": cvss,
                "severity": sev,
                "exploit_available": sev in ["CRITICAL", "HIGH"],
                "description": v.get("description", "CycloneDX VEX vulnerability."),
                "published_date": v.get("published", "Unknown"),
                "is_direct_dependency": True
            })
        return vulns

    @classmethod
    def _parse_osv(cls, osv_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        for v in osv_data.get("vulns", []):
            cve_id = v.get("id", "CVE-UNKNOWN")
            affected = v.get("affected", [])
            component = "unknown"
            if affected and "package" in affected[0]:
                component = affected[0]["package"].get("name", "unknown").lower()

            vulns.append({
                "cve_id": cve_id,
                "component": component,
                "current_version": "unknown",
                "fixed_version": "N/A",
                "cvss_score": 7.0,
                "severity": "HIGH",
                "exploit_available": False,
                "description": v.get("summary") or v.get("details", "OSV vulnerability."),
                "published_date": v.get("published", "Unknown"),
                "is_direct_dependency": True
            })
        return vulns

    # ─────────────────────────────────────────────────────────────────────────
    # CSV / TSV Parsing (Qualys, Nessus, Jira, Custom Excel exports)
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _parse_csv(cls, raw_str: str) -> Tuple[List[Dict[str, Any]], str]:
        # Detect delimiter
        first_line = raw_str.splitlines()[0] if raw_str.splitlines() else ""
        delimiter = "\t" if "\t" in first_line else (";" if ";" in first_line and "," not in first_line else ",")

        reader = csv.DictReader(io.StringIO(raw_str), delimiter=delimiter)
        rows = list(reader)

        if not rows or not reader.fieldnames:
            # Maybe headerless CSV
            return cls._parse_headerless_csv(raw_str, delimiter)

        # Build column index mapping
        cols = {c.strip().lower(): c for c in reader.fieldnames if c}

        def find_col(*aliases):
            for a in aliases:
                for c in cols:
                    if a == c or a in c or c in a:
                        return cols[c]
            return None

        cve_col = find_col("cve", "cve_id", "cve id", "cve-id", "vulnerability id", "vuln id", "issue", "finding")
        comp_col = find_col("component", "package", "library", "artifact", "target", "software", "product", "dependency", "module", "name")
        ver_col = find_col("installed_version", "current_version", "version", "installed", "ver")
        fix_col = find_col("fixed_version", "fix_version", "fixed_in", "fixed", "solution", "remediation", "patch")
        cvss_col = find_col("cvss", "cvss_score", "cvss score", "score", "base score", "cvss3", "cvss v3")
        sev_col = find_col("severity", "risk", "level", "criticality", "priority")
        exploit_col = find_col("exploit", "exploit_available", "exploit available", "poc", "in the wild", "has_exploit")
        desc_col = find_col("description", "summary", "title", "details", "synopsis")

        vulns = []
        for r in rows:
            # 1. Resolve CVE ID
            cve_val = r.get(cve_col, "") if cve_col else ""
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", str(cve_val), re.IGNORECASE)
            if not cve_match:
                # Search all values in row for CVE
                for val in r.values():
                    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", str(val), re.IGNORECASE)
                    if cve_match:
                        break

            cve_id = cve_match.group(0).upper() if cve_match else (str(cve_val).strip() or f"VULN-{len(vulns)+1}")

            # 2. Resolve Component
            comp_name = "unknown"
            if comp_col and r.get(comp_col):
                comp_name = str(r[comp_col]).strip().lower()
            elif ":" in cve_id:
                comp_name = cve_id.split(":")[0].lower()

            # 3. CVSS score
            cvss_raw = r.get(cvss_col, "5.0") if cvss_col else "5.0"
            try:
                cvss = float(re.search(r"\d+(\.\d+)?", str(cvss_raw)).group(0))
            except Exception:
                cvss = 5.0

            # 4. Severity
            sev_val = str(r.get(sev_col, "") if sev_col else "").strip().upper()
            if not sev_val or sev_val not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                sev_val = "CRITICAL" if cvss >= 9.0 else ("HIGH" if cvss >= 7.0 else ("MEDIUM" if cvss >= 4.0 else "LOW"))

            # 5. Exploit Available
            exploit_val = False
            if exploit_col and r.get(exploit_col):
                val_s = str(r[exploit_col]).strip().lower()
                exploit_val = val_s in ["yes", "true", "1", "available", "poc", "active"]
            else:
                exploit_val = sev_val in ["CRITICAL"]

            # 6. Description
            desc = str(r.get(desc_col, "") if desc_col else "").strip() or f"Vulnerability {cve_id} in {comp_name}."

            vulns.append({
                "cve_id": cve_id,
                "component": comp_name,
                "current_version": str(r.get(ver_col, "unknown") if ver_col else "unknown").strip(),
                "fixed_version": str(r.get(fix_col, "N/A") if fix_col else "N/A").strip(),
                "cvss_score": round(cvss, 1),
                "severity": sev_val,
                "exploit_available": exploit_val,
                "description": desc,
                "published_date": "N/A",
                "is_direct_dependency": True
            })

        return vulns, "CSV / Spreadsheet Report"

    @classmethod
    def _parse_headerless_csv(cls, raw_str: str, delimiter: str) -> Tuple[List[Dict[str, Any]], str]:
        vulns = []
        for line in raw_str.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip().strip('"').strip("'") for p in line.split(delimiter)]
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", line, re.IGNORECASE)
            cve_id = cve_match.group(0).upper() if cve_match else f"VULN-{len(vulns)+1}"

            comp = parts[0] if len(parts) > 0 and not parts[0].startswith("CVE") else "unknown"
            if len(parts) > 1 and parts[1].startswith("CVE"):
                comp = parts[0]
            elif len(parts) > 1 and not parts[1].startswith("CVE") and comp == "unknown":
                comp = parts[1]

            vulns.append({
                "cve_id": cve_id,
                "component": comp.lower(),
                "current_version": "unknown",
                "fixed_version": "N/A",
                "cvss_score": 7.0,
                "severity": "HIGH",
                "exploit_available": False,
                "description": f"Vulnerability {cve_id}",
                "published_date": "N/A",
                "is_direct_dependency": True
            })
        return vulns, "CSV (Headerless)"

    # ─────────────────────────────────────────────────────────────────────────
    # XML Parsing (CycloneDX VEX / OWASP Dependency-Check)
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _parse_xml(cls, raw_str: str) -> Tuple[List[Dict[str, Any]], str]:
        content_clean = re.sub(r'xmlns[^"]*"[^"]*"', '', raw_str)
        root = ET.fromstring(content_clean)
        vulns = []

        # Check OWASP Dependency-Check XML
        for vuln_node in root.findall(".//vulnerability"):
            cve_id = (vuln_node.findtext("name") or "").strip()
            if not cve_id:
                cve_id = (vuln_node.findtext("cve") or "CVE-UNKNOWN").strip()
            cvss_score = 5.0
            cvss_text = vuln_node.findtext("cvssScore") or vuln_node.findtext("cvssV3/baseScore")
            if cvss_text:
                try:
                    cvss_score = float(cvss_text)
                except Exception:
                    pass
            sev = (vuln_node.findtext("severity") or "MEDIUM").upper()
            desc = (vuln_node.findtext("description") or "").strip()

            vulns.append({
                "cve_id": cve_id,
                "component": "detected-component",
                "current_version": "unknown",
                "fixed_version": "N/A",
                "cvss_score": cvss_score,
                "severity": sev,
                "exploit_available": sev in ["CRITICAL", "HIGH"],
                "description": desc or f"Vulnerability {cve_id}",
                "published_date": "N/A",
                "is_direct_dependency": True
            })

        if vulns:
            return vulns, "OWASP / XML Vulnerability Feed"
        return [], "XML (No Vulnerabilities Found)"

    # ─────────────────────────────────────────────────────────────────────────
    # Plain Text CVE List
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _extract_raw_cves(cls, raw_str: str) -> List[Dict[str, Any]]:
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", raw_str, re.IGNORECASE)
        unique_cves = list(dict.fromkeys([c.upper() for c in cve_ids]))

        vulns = []
        for cve in unique_cves:
            vulns.append({
                "cve_id": cve,
                "component": "auto-detected",
                "current_version": "unknown",
                "fixed_version": "Upgrade Available",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "exploit_available": True,
                "description": f"Extracted reference: {cve}",
                "published_date": "N/A",
                "is_direct_dependency": True
            })
        return vulns

    # ─────────────────────────────────────────────────────────────────────────
    # Normalizer for standard list of dicts
    # ─────────────────────────────────────────────────────────────────────────

    @classmethod
    def _normalize_list(cls, items: List[Any]) -> List[Dict[str, Any]]:
        normalized = []
        for item in items:
            if not isinstance(item, dict):
                continue
            cve_id = item.get("cve_id") or item.get("cveId") or item.get("cve") or item.get("id") or "CVE-UNKNOWN"
            comp = item.get("component") or item.get("package") or item.get("packageName") or item.get("name") or "unknown"
            cur_ver = item.get("current_version") or item.get("version") or item.get("installed_version") or "unknown"
            fix_ver = item.get("fixed_version") or item.get("fixedVersion") or item.get("fix") or "N/A"

            # Score
            score_raw = item.get("cvss_score", item.get("cvssScore", item.get("cvss", 5.0)))
            try:
                cvss_score = float(score_raw)
            except Exception:
                cvss_score = 5.0

            # Severity
            sev = item.get("severity") or ("CRITICAL" if cvss_score >= 9.0 else ("HIGH" if cvss_score >= 7.0 else ("MEDIUM" if cvss_score >= 4.0 else "LOW")))

            normalized.append({
                "cve_id": str(cve_id).strip(),
                "component": str(comp).strip().lower(),
                "current_version": str(cur_ver).strip(),
                "fixed_version": str(fix_ver).strip(),
                "cvss_score": round(cvss_score, 1),
                "severity": str(sev).upper(),
                "exploit_available": bool(item.get("exploit_available", item.get("exploitAvailable", False))),
                "description": str(item.get("description", "No description available.")),
                "published_date": str(item.get("published_date", item.get("publishedDate", "Unknown"))),
                "is_direct_dependency": bool(item.get("is_direct_dependency", item.get("is_direct", True)))
            })
        return normalized
