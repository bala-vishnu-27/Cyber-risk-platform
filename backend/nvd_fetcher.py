"""
Module: NVD Fetcher + EPSS Score Integration
Fetches real-time CVE data from NIST NVD REST API 2.0
Fetches EPSS (Exploit Prediction Scoring System) scores from FIRST.org
Includes local file-based cache (24h TTL) to respect API rate limits.
"""
import json
import os
import time
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Any

CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".nvd_cache")
CACHE_TTL_SECONDS = 86400  # 24 hours

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"


def _ensure_cache_dir():
    os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_path(key: str) -> str:
    safe_key = key.replace("/", "_").replace(":", "_")
    return os.path.join(CACHE_DIR, f"{safe_key}.json")


def _read_cache(key: str) -> Optional[Any]:
    path = _cache_path(key)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            cached = json.load(f)
        if time.time() - cached.get("timestamp", 0) < CACHE_TTL_SECONDS:
            return cached["data"]
    except Exception:
        pass
    return None


def _write_cache(key: str, data: Any):
    _ensure_cache_dir()
    path = _cache_path(key)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"timestamp": time.time(), "data": data}, f)
    except Exception:
        pass


def fetch_cve_details(cve_id: str) -> Optional[Dict]:
    """
    Fetch a single CVE's detailed information from NVD REST API 2.0.
    Returns a normalized dict with description, CVSS, CWE, references.
    """
    cached = _read_cache(f"nvd_{cve_id}")
    if cached is not None:
        return cached

    try:
        url = f"{NVD_API_BASE}?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberRiskPlatform/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = json.loads(resp.read().decode("utf-8"))

        vulns = raw.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # Parse CVSS v3.1 or v3.0 or v2
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        severity = "UNKNOWN"
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                break

        # CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("lang") == "en":
                    cwes.append(d["value"])

        # References
        references = [r.get("url") for r in cve_data.get("references", [])[:5] if r.get("url")]

        # Published / Modified dates
        published = cve_data.get("published", "Unknown")[:10]
        modified = cve_data.get("lastModified", "Unknown")[:10]

        result = {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity.upper(),
            "cwes": cwes,
            "references": references,
            "published_date": published,
            "last_modified": modified,
            "source": "NVD_LIVE"
        }
        _write_cache(f"nvd_{cve_id}", result)
        return result

    except Exception as e:
        return {"error": str(e), "source": "NVD_ERROR"}


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, Dict]:
    """
    Fetch EPSS (Exploit Prediction Scoring System) scores for a list of CVE IDs.
    Returns a dict: { "CVE-2021-44228": { "epss": 0.975, "percentile": 0.99 }, ... }
    """
    if not cve_ids:
        return {}

    # Check cache first
    cache_key = "epss_" + "_".join(sorted(cve_ids[:20]))
    cached = _read_cache(cache_key)
    if cached is not None:
        return cached

    result = {}
    try:
        # EPSS API supports comma-separated CVE IDs (up to 100 at a time)
        chunk_size = 100
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i : i + chunk_size]
            cve_param = ",".join(chunk)
            url = f"{EPSS_API_BASE}?cve={urllib.parse.quote(cve_param)}"
            req = urllib.request.Request(url, headers={"User-Agent": "CyberRiskPlatform/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for entry in data.get("data", []):
                cve = entry.get("cve", "")
                result[cve] = {
                    "epss": round(float(entry.get("epss", 0.0)), 4),
                    "percentile": round(float(entry.get("percentile", 0.0)), 4),
                    "date": entry.get("date", "")
                }
            time.sleep(0.5)  # Rate limit respect

        _write_cache(cache_key, result)

    except Exception as e:
        # Return empty if EPSS API fails; platform still works without EPSS
        pass

    return result


def enrich_vulnerabilities_with_live_data(matched_vulns: List[Dict]) -> List[Dict]:
    """
    Enriches matched vulnerability list with:
    - Live NVD CVE descriptions, CVSS vectors, CWEs, references
    - EPSS exploit prediction scores
    Returns enriched list.
    """
    if not matched_vulns:
        return matched_vulns

    # Fetch EPSS for all CVE IDs in one batch
    cve_ids = [v.get("cve_id", "") for v in matched_vulns if v.get("cve_id", "").startswith("CVE-")]
    epss_data = fetch_epss_scores(cve_ids)

    enriched = []
    for vuln in matched_vulns:
        cve_id = vuln.get("cve_id", "")
        epss_info = epss_data.get(cve_id, {})

        # Attempt NVD enrichment (skip for generated/fake CVEs)
        nvd_info = {}
        if cve_id.startswith("CVE-") and len(cve_id) <= 20:
            nvd_info = fetch_cve_details(cve_id) or {}

        enriched_vuln = {
            **vuln,
            "epss_score": epss_info.get("epss", None),
            "epss_percentile": epss_info.get("percentile", None),
            "cvss_vector": nvd_info.get("cvss_vector", None),
            "cwes": nvd_info.get("cwes", []),
            "references": nvd_info.get("references", []),
            "last_modified": nvd_info.get("last_modified", None),
            "data_source": nvd_info.get("source", "LOCAL")
        }

        # Override description/cvss from NVD if available and higher quality
        if nvd_info.get("description") and not nvd_info.get("error"):
            enriched_vuln["description"] = nvd_info["description"]
        if nvd_info.get("cvss_score") and nvd_info["cvss_score"] != vuln.get("cvss_score"):
            enriched_vuln["cvss_score_nvd"] = nvd_info["cvss_score"]

        enriched.append(enriched_vuln)

    return enriched


def clear_cache():
    """Clear all cached NVD/EPSS data."""
    import shutil
    if os.path.exists(CACHE_DIR):
        shutil.rmtree(CACHE_DIR)
