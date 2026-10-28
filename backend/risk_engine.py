"""
Module 4 & 5: Risk Scoring Engine & Prioritization Engine (Enhanced)
Calculates 0-100 Risk Score using 6 weighted factors:
  1. CVSS Severity           (35%) — down from 40% to make room for EPSS
  2. EPSS Exploit Probability (5%) — NEW: real-world exploit likelihood
  3. Internet Exposure       (25%)
  4. Business Criticality    (20%)
  5. Exploit Availability    (10%)
  6. Dependency Importance    (5%)

Also generates:
  - Risk threshold alerts (CRITICAL alert when score ≥ 80)
  - Per-vulnerability SLA deadline recommendations
"""
from typing import Dict, List, Any
from datetime import datetime, timedelta


class RiskScoringEngine:
    """
    Module 4 & 5: Risk Scoring Engine & Prioritization Engine
    Calculates 0-100 Risk Score using 6 weighted factors.
    """

    # Risk score thresholds that trigger alerts
    ALERT_THRESHOLD_CRITICAL = 80.0
    ALERT_THRESHOLD_HIGH = 60.0

    # SLA hours by risk tier
    SLA_HOURS = {
        "CRITICAL": 24,
        "HIGH": 168,       # 7 days
        "MEDIUM": 720,     # 30 days
        "LOW": 2160        # 90 days
    }

    @staticmethod
    def calculate_risk_scores(
        matched_vulns: List[Dict[str, Any]],
        app_details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Applies weighted risk scoring algorithm to each vulnerability,
        ranks them from highest to lowest risk score, and calculates
        overall application risk score plus threshold alerts.
        """
        # Parse App Context
        exposure_setting = str(app_details.get("internet_exposure", "High")).strip().lower()
        if exposure_setting in ["high", "public", "yes", "true"]:
            exposure_score = 10.0
        elif exposure_setting in ["medium", "internal"]:
            exposure_score = 5.0
        else:
            exposure_score = 2.0

        criticality_setting = str(app_details.get("business_criticality", "High")).strip().lower()
        if criticality_setting in ["high", "critical"]:
            criticality_score = 10.0
        elif criticality_setting in ["medium", "standard"]:
            criticality_score = 6.0
        else:
            criticality_score = 3.0

        prioritized_vulns = []
        total_risk_sum = 0
        now = datetime.utcnow()

        for vuln in matched_vulns:
            cvss = float(vuln.get("cvss_score", 5.0))
            exploit = 10.0 if vuln.get("exploit_available", False) else 2.0
            dep_importance = 10.0 if vuln.get("is_direct_dependency", True) else 4.0

            # EPSS score (0.0–1.0) → scale to 0–10
            epss_raw = vuln.get("epss_score")
            if epss_raw is not None:
                epss_score_scaled = float(epss_raw) * 10.0
            else:
                # Fallback: use exploit availability as proxy
                epss_score_scaled = 7.0 if vuln.get("exploit_available", False) else 2.0

            # ── Weighted formula (Sum of weights = 100%) ──────────────────────
            # CVSS (35%)           → cvss * 3.5
            # EPSS (5%)            → epss_score_scaled * 0.5
            # Exposure (25%)       → exposure_score * 2.5
            # Criticality (20%)    → criticality_score * 2.0
            # Exploit (10%)        → exploit * 1.0
            # Dependency (5%)      → dep_importance * 0.5
            # ─────────────────────────────────────────────────────────────────
            cvss_contrib        = round(cvss * 3.5, 1)
            epss_contrib        = round(epss_score_scaled * 0.5, 1)
            exposure_contrib    = round(exposure_score * 2.5, 1)
            criticality_contrib = round(criticality_score * 2.0, 1)
            exploit_contrib     = round(exploit * 1.0, 1)
            dep_contrib         = round(dep_importance * 0.5, 1)

            risk_score = round(
                cvss_contrib + epss_contrib + exposure_contrib +
                criticality_contrib + exploit_contrib + dep_contrib,
                1
            )
            risk_score = min(100.0, risk_score)

            # Risk Tier
            if risk_score >= 80.0:
                risk_tier = "CRITICAL"
            elif risk_score >= 60.0:
                risk_tier = "HIGH"
            elif risk_score >= 40.0:
                risk_tier = "MEDIUM"
            else:
                risk_tier = "LOW"

            # SLA Deadline
            sla_hours = RiskScoringEngine.SLA_HOURS.get(risk_tier, 720)
            sla_deadline = (now + timedelta(hours=sla_hours)).strftime("%Y-%m-%d %H:%M UTC")

            prioritized_vulns.append({
                **vuln,
                "risk_score": risk_score,
                "risk_tier": risk_tier,
                "sla_deadline": sla_deadline,
                "sla_hours": sla_hours,
                "factor_breakdown": {
                    "cvss_contrib": cvss_contrib,
                    "epss_contrib": epss_contrib,
                    "exposure_contrib": exposure_contrib,
                    "criticality_contrib": criticality_contrib,
                    "exploit_contrib": exploit_contrib,
                    "dep_contrib": dep_contrib
                },
                "risk_explanation": (
                    f"Risk Score of {risk_score}/100 driven by CVSS {cvss} ({cvss_contrib} pts), "
                    f"Internet Exposure ({exposure_contrib} pts), Business Criticality ({criticality_contrib} pts)"
                    + (f", EPSS {epss_raw:.1%} ({epss_contrib} pts)" if epss_raw is not None else "") + "."
                )
            })
            total_risk_sum += risk_score

        # Sort highest → lowest
        prioritized_vulns.sort(key=lambda x: x["risk_score"], reverse=True)

        # Overall Application Score (weighted average of top 3)
        overall_app_score = 0.0
        if prioritized_vulns:
            top_3 = prioritized_vulns[:3]
            overall_app_score = round(sum(v["risk_score"] for v in top_3) / len(top_3), 1)

        overall_tier = (
            "CRITICAL" if overall_app_score >= 80 else
            "HIGH"     if overall_app_score >= 60 else
            "MEDIUM"   if overall_app_score >= 40 else "LOW"
        )

        # ── Threshold Alerts ────────────────────────────────────────────────
        alerts = []
        if overall_app_score >= RiskScoringEngine.ALERT_THRESHOLD_CRITICAL:
            alerts.append({
                "level": "CRITICAL",
                "message": (
                    f"Application '{app_details.get('app_name', 'Unknown')}' has reached "
                    f"CRITICAL risk threshold ({overall_app_score}/100). "
                    "Immediate remediation required within 24 hours."
                ),
                "triggered_at": now.strftime("%Y-%m-%d %H:%M UTC")
            })
        elif overall_app_score >= RiskScoringEngine.ALERT_THRESHOLD_HIGH:
            alerts.append({
                "level": "HIGH",
                "message": (
                    f"Application risk score is HIGH ({overall_app_score}/100). "
                    "Prioritize remediation within 7 days."
                ),
                "triggered_at": now.strftime("%Y-%m-%d %H:%M UTC")
            })

        # Alert for exploitable critical CVEs
        exploitable_criticals = [
            v["cve_id"] for v in prioritized_vulns
            if v["risk_tier"] == "CRITICAL" and v.get("exploit_available", False)
        ]
        if exploitable_criticals:
            alerts.append({
                "level": "CRITICAL",
                "message": (
                    f"{len(exploitable_criticals)} vulnerabilities have both CRITICAL risk score "
                    f"AND publicly available exploit code: {', '.join(exploitable_criticals[:5])}."
                ),
                "triggered_at": now.strftime("%Y-%m-%d %H:%M UTC")
            })

        return {
            "overall_app_score": overall_app_score,
            "overall_tier": overall_tier,
            "total_vulnerabilities": len(prioritized_vulns),
            "critical_count": sum(1 for v in prioritized_vulns if v["risk_tier"] == "CRITICAL"),
            "high_count":     sum(1 for v in prioritized_vulns if v["risk_tier"] == "HIGH"),
            "medium_count":   sum(1 for v in prioritized_vulns if v["risk_tier"] == "MEDIUM"),
            "low_count":      sum(1 for v in prioritized_vulns if v["risk_tier"] == "LOW"),
            "alerts": alerts,
            "epss_enabled": any(v.get("epss_score") is not None for v in prioritized_vulns),
            "prioritized_list": prioritized_vulns
        }
