"""
Module 6: Remediation Recommender (Enhanced)
Generates tailored, actionable remediation recommendations with:
  - Package-manager aware CLI commands (pip/npm/mvn/go/composer)
  - SLA-based urgency timelines with exact deadlines
  - Risk-based workaround strategies
  - CWE-aware remediation guidance
"""
from typing import Dict, List, Any


# Package manager detection by component purl prefix
_PKG_MANAGER_HINTS = {
    "pkg:pypi":    "pip",
    "pkg:npm":     "npm",
    "pkg:maven":   "mvn",
    "pkg:golang":  "go",
    "pkg:composer": "composer",
    "pkg:gem":     "gem",
    "pkg:cargo":   "cargo",
    "pkg:nuget":   "dotnet",
}

# CWE-specific guidance
_CWE_GUIDANCE = {
    "CWE-79":  "Ensure output encoding and implement Content-Security-Policy headers.",
    "CWE-89":  "Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
    "CWE-502": "Restrict deserialization to trusted classes using allowlists. Upgrade library.",
    "CWE-22":  "Validate and canonicalize all file paths. Reject paths with '..' traversal sequences.",
    "CWE-78":  "Avoid shell interpolation of user input. Use subprocess lists instead of shell=True.",
    "CWE-434": "Validate file types server-side. Restrict upload directories from web access.",
    "CWE-611": "Disable XML external entity (XXE) processing in parsers.",
    "CWE-918": "Validate and allowlist URLs before making server-side requests.",
}


def _detect_pkg_manager(purl: str, component: str) -> str:
    if purl:
        for prefix, mgr in _PKG_MANAGER_HINTS.items():
            if purl.lower().startswith(prefix):
                return mgr
    # Heuristic from component name
    if any(component.endswith(x) for x in ["-core", "-framework", ".jar"]):
        return "mvn"
    return "pip"  # default


def _build_cli_command(pkg_manager: str, component: str, fix_version: str) -> str:
    if fix_version == "N/A":
        return f"# Consult vendor advisory — no fix version available for {component}"

    cmds = {
        "pip":      f"pip install --upgrade '{component}>={fix_version}'",
        "npm":      f"npm install {component}@{fix_version}",
        "mvn":      f"mvn versions:use-dep-version -Dincludes={component} -DdepVersion={fix_version}",
        "go":       f"go get {component}@v{fix_version}",
        "composer": f"composer require {component}:{fix_version}",
        "gem":      f"gem update {component} --version {fix_version}",
        "cargo":    f"cargo update -p {component} --precise {fix_version}",
        "dotnet":   f"dotnet add package {component} --version {fix_version}",
    }
    return cmds.get(pkg_manager, f"pip install --upgrade '{component}>={fix_version}'")


class RemediationRecommender:
    """
    Module 6: Remediation Recommender
    Generates tailored, actionable remediation recommendations, upgrade versions,
    package-manager aware patch commands, SLA timelines, and CWE guidance.
    """

    @staticmethod
    def generate_recommendations(prioritized_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enhances prioritized vulnerabilities with actionable fix advice.
        """
        recommendations = []

        for item in prioritized_list:
            comp      = item["component"]
            curr_ver  = item["current_version"]
            fix_ver   = item["fixed_version"]
            cve_id    = item["cve_id"]
            risk_tier = item["risk_tier"]
            risk_score = item["risk_score"]
            purl      = item.get("purl", "")
            cwes      = item.get("cwes", [])
            sla_deadline = item.get("sla_deadline", "")
            sla_hours    = item.get("sla_hours", 720)

            pkg_manager = _detect_pkg_manager(purl, comp)

            if fix_ver != "N/A":
                primary_action = (
                    f"Upgrade {comp} from {curr_ver} to {fix_ver} or higher "
                    f"using {pkg_manager}."
                )
                cli_command = _build_cli_command(pkg_manager, comp, fix_ver)
                strategy = "Version Upgrade"
            else:
                primary_action = (
                    f"No direct fix version available for {comp} {curr_ver}. "
                    "Apply vendor security patch, restrict network access, or consider alternative library."
                )
                cli_command = f"# Check vendor advisory: https://nvd.nist.gov/vuln/detail/{cve_id}"
                strategy = "Workaround / Vendor Advisory"

            # Urgency with specific SLA deadline
            if risk_tier == "CRITICAL":
                urgency = f"IMMEDIATE — Fix within 24 hours (by {sla_deadline})"
            elif risk_tier == "HIGH":
                urgency = f"HIGH PRIORITY — Fix within 7 days (by {sla_deadline})"
            elif risk_tier == "MEDIUM":
                urgency = f"STANDARD — Fix in next release cycle within 30 days (by {sla_deadline})"
            else:
                urgency = f"LOW — Address in next planned maintenance (by {sla_deadline})"

            # Workaround advice
            workaround = (
                f"If upgrade of {comp} cannot be completed immediately, "
                f"consider restricting network access to endpoints using {comp}, "
                f"enabling WAF rules for {cve_id}, and monitoring for exploitation indicators."
            )

            # CWE-specific guidance
            cwe_advice = []
            for cwe in cwes[:2]:  # top 2 CWEs
                cwe_id_clean = cwe.replace("CWE-", "CWE-")
                if cwe_id_clean in _CWE_GUIDANCE:
                    cwe_advice.append(_CWE_GUIDANCE[cwe_id_clean])

            # CI/CD integration snippet
            ci_check = (
                f"# GitHub Actions — Block merge if {comp}<{fix_ver} is detected:\n"
                f"# uses: actions/dependency-review-action@v3\n"
                f"# with:\n#   fail-on-severity: {'critical' if risk_tier == 'CRITICAL' else 'high'}"
                if fix_ver != "N/A" else
                f"# Monitor {cve_id} in your dependency scanning CI step"
            )

            recommendations.append({
                **item,
                "remediation": {
                    "strategy": strategy,
                    "primary_action": primary_action,
                    "target_version": fix_ver,
                    "cli_command": cli_command,
                    "package_manager": pkg_manager,
                    "urgency": urgency,
                    "sla_hours": sla_hours,
                    "sla_deadline": sla_deadline,
                    "workaround": workaround,
                    "cwe_guidance": cwe_advice,
                    "ci_integration_hint": ci_check
                }
            })

        return recommendations
