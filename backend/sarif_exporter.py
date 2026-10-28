"""
Module: SARIF Exporter
Converts Cyber Risk Platform analysis results to SARIF 2.1.0 format.
SARIF (Static Analysis Results Interchange Format) is used by GitHub Security,
GitLab SAST, and major CI/CD platforms.
"""
import json
from typing import Dict, List, Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "CyberRiskPlatform"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://github.com/your-org/cyber-risk-platform"


def export_sarif(analysis_result: Dict) -> Dict:
    """
    Converts a full analysis result payload into SARIF 2.1.0 format.
    Returns a SARIF-compliant dict ready to be serialized to JSON.
    """
    remediations: List[Dict] = analysis_result.get("remediations", [])
    application: Dict = analysis_result.get("application", {})
    app_name: str = application.get("app_name", "Unknown Application")

    # Build rules (one per unique CVE)
    rules = []
    rules_seen = set()
    results = []

    for item in remediations:
        cve_id: str = item.get("cve_id", "CVE-UNKNOWN")
        component: str = item.get("component", "unknown")
        description: str = item.get("description", "No description.")
        severity: str = item.get("severity", "MEDIUM")
        cvss: float = item.get("cvss_score", 5.0)
        risk_score: float = item.get("risk_score", 0.0)
        risk_tier: str = item.get("risk_tier", "MEDIUM")
        fix_ver: str = item.get("fixed_version", "N/A")
        references: List[str] = item.get("references", [])

        # SARIF rule per CVE
        if cve_id not in rules_seen:
            rules_seen.add(cve_id)
            rule = {
                "id": cve_id,
                "name": f"VulnerableComponent/{cve_id}",
                "shortDescription": {"text": f"{cve_id} in {component}"},
                "fullDescription": {"text": description},
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "properties": {
                    "cvssScore": cvss,
                    "severity": severity,
                    "tags": ["security", "dependency", severity.lower()]
                }
            }
            if references:
                rule["help"] = {"text": "\n".join(references)}
            rules.append(rule)

        # SARIF level mapping
        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        sarif_level = level_map.get(risk_tier, "warning")

        # Build result
        message_text = (
            f"[{cve_id}] {component} has a {severity} severity vulnerability "
            f"(CVSS: {cvss}, Risk Score: {risk_score}/100). "
        )
        if fix_ver != "N/A":
            message_text += f"Upgrade to version {fix_ver} to remediate."
        else:
            message_text += "No fix version available; apply vendor mitigation."

        result_entry = {
            "ruleId": cve_id,
            "level": sarif_level,
            "message": {"text": message_text},
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": component,
                            "decoratedName": f"{component}@{item.get('current_version', 'unknown')}",
                            "kind": "package"
                        }
                    ]
                }
            ],
            "properties": {
                "riskScore": risk_score,
                "riskTier": risk_tier,
                "epssScore": item.get("epss_score"),
                "exploitAvailable": item.get("exploit_available", False),
                "fixedVersion": fix_ver,
                "application": app_name
            }
        }

        # Add web request context if internet-exposed
        if application.get("internet_exposure") == "High":
            result_entry["webRequest"] = {
                "target": f"/{component}/endpoint",
                "protocol": "HTTPS"
            }

        results.append(result_entry)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rules
                    }
                },
                "results": results,
                "properties": {
                    "applicationName": app_name,
                    "applicationType": application.get("app_type", ""),
                    "businessCriticality": application.get("business_criticality", ""),
                    "internetExposure": application.get("internet_exposure", ""),
                    "overallRiskScore": analysis_result.get("risk_summary", {}).get("overall_app_score", 0),
                    "overallTier": analysis_result.get("risk_summary", {}).get("overall_tier", "")
                }
            }
        ]
    }

    return sarif_doc


def export_sarif_string(analysis_result: Dict) -> str:
    """Returns SARIF output as a formatted JSON string."""
    return json.dumps(export_sarif(analysis_result), indent=2)
