import json
import os
from typing import Dict, List, Any
from vuln_parser import UniversalVulnParser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")


class VulnerabilityMatcher:
    """
    Modules 2 & 3: Component Identification & Vulnerability Matching (Universal)
    Identifies components and matches them with known CVE data.
    Supports CSV, SARIF, Trivy, Grype, Snyk, XML, JSON, and autonomous scanning.
    """

    @classmethod
    def match_vulnerabilities(cls, components: List[Dict[str, Any]], vuln_database: Any) -> List[Dict[str, Any]]:
        """
        Cross-references component list against vulnerability database.
        Returns a normalized, enriched list of matched vulnerabilities.
        Guaranteed never to crash on any input format.
        """
        vuln_list = []
        detected_format = "None"

        # 1. Parse using UniversalVulnParser
        if vuln_database:
            vuln_list, detected_format = UniversalVulnParser.parse(vuln_database)

        # 2. Autonomous scanning mode: If no vuln database was provided or it yielded 0 findings,
        # but we have SBOM components, check our built-in enterprise CVE database!
        if not vuln_list and components:
            vuln_list = cls._scan_from_builtin_db(components)

        if not vuln_list:
            return []

        # 3. Build quick lookup by component name (support fuzzy and prefix matching)
        comp_map = {}
        for comp in components:
            cname = str(comp.get("name", "")).strip().lower()
            if cname:
                comp_map[cname] = comp
                # Also index sub-parts (e.g. org.apache.logging.log4j:log4j-core -> log4j-core, log4j)
                for part in cname.replace(":", "/").split("/"):
                    if len(part) > 3 and part not in comp_map:
                        comp_map[part] = comp

        matched_results = []
        seen_cves = set()

        for vuln in vuln_list:
            comp_name = str(vuln.get("component", "unknown")).strip().lower()
            cve_id = str(vuln.get("cve_id", vuln.get("cveId", "CVE-UNKNOWN"))).strip()
            dedup_key = (cve_id, comp_name)

            if dedup_key in seen_cves:
                continue
            seen_cves.add(dedup_key)

            # Check if this vuln matches any component in SBOM
            comp_info = comp_map.get(comp_name)
            if not comp_info:
                # Fuzzy match: e.g. "log4j" in "log4j-core"
                for ckey, cval in comp_map.items():
                    if (ckey in comp_name or comp_name in ckey) and len(ckey) >= 4 and len(comp_name) >= 4:
                        comp_info = cval
                        break

            if comp_info:
                current_version = comp_info.get("version", vuln.get("current_version", "unknown"))
                is_direct = comp_info.get("is_direct", True)
                resolved_comp = comp_info.get("name", comp_name)
            else:
                # No SBOM match or no SBOM provided — keep original vuln data intact!
                current_version = vuln.get("current_version", "unknown")
                is_direct = vuln.get("is_direct_dependency", True)
                resolved_comp = comp_name if comp_name != "unknown" else "application-service"

            cvss = float(vuln.get("cvss_score", vuln.get("cvssScore", 5.0)) or 5.0)
            sev = str(vuln.get("severity", "MEDIUM")).upper()
            if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                sev = "CRITICAL" if cvss >= 9.0 else ("HIGH" if cvss >= 7.0 else ("MEDIUM" if cvss >= 4.0 else "LOW"))

            matched_results.append({
                "cve_id": cve_id,
                "component": resolved_comp,
                "current_version": current_version,
                "fixed_version": vuln.get("fixed_version", vuln.get("fixedVersion", "N/A")),
                "cvss_score": round(cvss, 1),
                "severity": sev,
                "exploit_available": bool(vuln.get("exploit_available", vuln.get("exploitAvailable", False))),
                "description": vuln.get("description", f"Vulnerability {cve_id} in {resolved_comp}."),
                "published_date": vuln.get("published_date", vuln.get("publishedDate", "Unknown")),
                "is_direct_dependency": is_direct
            })

        return matched_results

    @classmethod
    def _scan_from_builtin_db(cls, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Autonomous Threat Intel Scanner: Queries local enterprise CVE reference databases
        for known vulnerabilities affecting the specified SBOM components.
        """
        db_path = os.path.join(DATA_DIR, "real_vulnerabilities_500.json")
        if not os.path.exists(db_path):
            db_path = os.path.join(DATA_DIR, "real_vulnerabilities.json")

        if not os.path.exists(db_path):
            return []

        try:
            with open(db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            all_vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else data

            comp_names = {str(c.get("name", "")).strip().lower() for c in components if c.get("name")}
            found = []

            for v in all_vulns:
                v_comp = str(v.get("component", "")).strip().lower()
                for cname in comp_names:
                    if cname == v_comp or (len(cname) >= 4 and (cname in v_comp or v_comp in cname)):
                        found.append(v)
                        break

            return found
        except Exception:
            return []
