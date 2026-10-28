"""
Module: HTML Report Generator
Generates a professional, print-ready HTML executive security report.
Users can open it in a browser and Ctrl+P → Save as PDF (no external deps needed).
Supports Risk Score gauge, severity breakdown table, remediation action list,
EPSS intelligence, and scan metadata.
"""
from typing import Dict, Any
import json


def _severity_color(tier: str) -> str:
    return {
        "CRITICAL": "#ff2a5f",
        "HIGH": "#ff7a00",
        "MEDIUM": "#ffc700",
        "LOW": "#00e676"
    }.get(tier.upper(), "#94a3b8")


def _risk_gauge_svg(score: float, tier: str) -> str:
    color = _severity_color(tier)
    pct = min(score / 100.0, 1.0)
    # SVG arc from 225° to 315° (270° sweep = 3/4 circle)
    import math
    r = 70
    cx, cy = 90, 90
    start_angle = 225
    sweep = 270 * pct
    end_angle = start_angle + sweep

    def polar(deg):
        rad = math.radians(deg)
        return cx + r * math.cos(rad), cy + r * math.sin(rad)

    sx, sy = polar(start_angle)
    ex, ey = polar(end_angle)
    large_arc = 1 if sweep > 180 else 0
    track_ex, track_ey = polar(start_angle + 270)

    return f"""
    <svg width="180" height="160" viewBox="0 0 180 180">
      <!-- Track arc -->
      <path d="M {sx:.1f} {sy:.1f} A {r} {r} 0 1 1 {track_ex:.1f} {track_ey:.1f}"
            fill="none" stroke="#1e293b" stroke-width="14" stroke-linecap="round"/>
      <!-- Score arc -->
      {'<path d="M ' + f'{sx:.1f} {sy:.1f} A {r} {r} 0 {large_arc} 1 {ex:.1f} {ey:.1f}"' +
       f' fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"/>' if pct > 0 else ''}
      <!-- Score text -->
      <text x="90" y="95" text-anchor="middle" fill="white"
            font-size="32" font-weight="800" font-family="system-ui">{score}</text>
      <text x="90" y="115" text-anchor="middle" fill="{color}"
            font-size="13" font-weight="700" font-family="system-ui">{tier} RISK</text>
      <text x="90" y="130" text-anchor="middle" fill="#64748b"
            font-size="10" font-family="system-ui">/ 100</text>
    </svg>"""


def generate_html_report(analysis_result: Dict, scan_id: int = None) -> str:
    """
    Generate a complete, standalone HTML executive security report.
    """
    app = analysis_result.get("application", {})
    summary = analysis_result.get("risk_summary", {})
    remediations = analysis_result.get("remediations", [])

    app_name = app.get("app_name", "Unknown App")
    app_type = app.get("app_type", "")
    exposure = app.get("internet_exposure", "")
    criticality = app.get("business_criticality", "")
    overall_score = summary.get("overall_app_score", 0)
    overall_tier = summary.get("overall_tier", "LOW")
    total_vulns = summary.get("total_vulnerabilities", 0)
    critical_cnt = summary.get("critical_count", 0)
    high_cnt = summary.get("high_count", 0)
    medium_cnt = summary.get("medium_count", 0)
    low_cnt = summary.get("low_count", 0)

    tier_color = _severity_color(overall_tier)
    gauge_svg = _risk_gauge_svg(overall_score, overall_tier)

    # Build vulnerability rows
    rows_html = ""
    for i, item in enumerate(remediations[:100], 1):  # cap at 100 for PDF readability
        cve = item.get("cve_id", "")
        comp = item.get("component", "")
        ver = item.get("current_version", "")
        fix = item.get("fixed_version", "N/A")
        cvss = item.get("cvss_score", "")
        epss = item.get("epss_score")
        tier = item.get("risk_tier", "LOW")
        rs = item.get("risk_score", 0)
        exploit = item.get("exploit_available", False)
        action = item.get("remediation", {}).get("primary_action", "")
        urgency = item.get("remediation", {}).get("urgency", "")
        tc = _severity_color(tier)
        epss_badge = f'<span style="color:#a5f3fc;font-size:11px">EPSS: {epss:.1%}</span>' if epss is not None else ""

        rows_html += f"""
        <tr>
          <td style="color:#94a3b8;font-weight:700;text-align:center">{i}</td>
          <td style="font-weight:800;color:{tc}">{rs}<span style="font-size:11px;color:#64748b">/100</span></td>
          <td style="font-family:monospace;color:#00f2fe;font-size:12px">{cve}</td>
          <td><strong>{comp}</strong><br><span style="color:#64748b;font-size:11px">v{ver}</span></td>
          <td style="text-align:center">
            <span style="background:{tc}22;color:{tc};border:1px solid {tc}55;
                   padding:3px 10px;border-radius:6px;font-size:12px;font-weight:700">{tier}</span>
          </td>
          <td style="font-weight:700">{cvss}</td>
          <td style="text-align:center">{'<span style="color:#ff2a5f;font-weight:700">YES</span>' if exploit else '<span style="color:#64748b">No</span>'}</td>
          <td style="font-size:12px">{action}<br>{epss_badge}</td>
          <td style="font-size:11px;color:#ff7a00">{urgency}</td>
        </tr>"""

    from datetime import datetime
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Risk Report — {app_name}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap');
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Plus Jakarta Sans', system-ui, sans-serif; background: #070a12; color: #f8fafc; padding: 40px; min-height: 100vh; }}
    @media print {{
      body {{ background: white; color: #1e293b; padding: 20px; }}
      .no-print {{ display: none !important; }}
      table {{ page-break-inside: auto; }}
      tr {{ page-break-inside: avoid; page-break-after: auto; }}
      thead {{ display: table-header-group; }}
    }}
    .report-header {{ display: flex; justify-content: space-between; align-items: flex-start;
                      margin-bottom: 40px; padding-bottom: 28px; border-bottom: 2px solid #0f172a; }}
    .report-title {{ font-size: 28px; font-weight: 800; color: #00f2fe; margin-bottom: 6px; }}
    .report-meta {{ font-size: 13px; color: #64748b; line-height: 1.6; }}
    .report-badge {{ background: {tier_color}22; border: 2px solid {tier_color}66;
                     border-radius: 12px; padding: 8px 20px; text-align: center; }}
    .report-badge .rb-score {{ font-size: 36px; font-weight: 800; color: {tier_color}; }}
    .report-badge .rb-label {{ font-size: 12px; color: {tier_color}; font-weight: 700; }}
    .summary-grid {{ display: grid; grid-template-columns: auto 1fr 1fr 1fr 1fr; gap: 20px;
                     margin-bottom: 40px; align-items: center; }}
    .gauge-wrap {{ text-align: center; }}
    .stat-box {{ background: #0b101d; border: 1px solid #1e293b; border-radius: 12px;
                 padding: 18px; text-align: center; }}
    .stat-num {{ font-size: 32px; font-weight: 800; display: block; margin-bottom: 4px; }}
    .stat-label {{ font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; }}
    .section-title {{ font-size: 16px; font-weight: 800; color: #94a3b8; text-transform: uppercase;
                      letter-spacing: 1px; margin-bottom: 16px; display: flex; align-items: center; gap: 10px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 40px; }}
    thead tr {{ background: #0b101d; }}
    th {{ padding: 12px 14px; text-align: left; font-size: 11px; font-weight: 800;
          color: #64748b; text-transform: uppercase; border-bottom: 1px solid #1e293b; }}
    td {{ padding: 14px 14px; border-bottom: 1px solid #0f172a; vertical-align: top; }}
    tbody tr:hover {{ background: #0b101d; }}
    .app-ctx {{ background: #0b101d; border: 1px solid #1e293b; border-radius: 12px; padding: 20px;
                margin-bottom: 28px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }}
    .ctx-item {{ font-size: 12px; color: #64748b; font-weight: 700; }}
    .ctx-val {{ font-size: 14px; color: #f8fafc; font-weight: 800; margin-top: 4px; }}
    .footer {{ margin-top: 40px; text-align: center; font-size: 12px; color: #334155;
               padding-top: 20px; border-top: 1px solid #1e293b; }}
    .print-btn {{ position: fixed; top: 24px; right: 24px; background: #00f2fe; color: #070a12;
                  border: none; padding: 12px 24px; border-radius: 8px; font-weight: 800;
                  font-size: 14px; cursor: pointer; box-shadow: 0 0 20px rgba(0,242,254,0.4); }}
    .print-btn:hover {{ transform: translateY(-2px); }}
  </style>
</head>
<body>
  <button class="print-btn no-print" onclick="window.print()">⬇ Save as PDF</button>

  <div class="report-header">
    <div>
      <div class="report-title">🛡 Cyber Risk Prioritization Report</div>
      <div class="report-meta">
        <strong>Application:</strong> {app_name}<br>
        <strong>Generated:</strong> {now_str}{' &nbsp;|&nbsp; <strong>Scan ID:</strong> ' + str(scan_id) if scan_id else ''}<br>
        <strong>Platform:</strong> Cyber Risk Prioritization Platform v1.0
      </div>
    </div>
    <div class="report-badge">
      <div class="rb-score">{overall_score}</div>
      <div class="rb-label">/ 100 — {overall_tier} RISK</div>
    </div>
  </div>

  <div class="app-ctx">
    <div><div class="ctx-item">Application Type</div><div class="ctx-val">{app_type}</div></div>
    <div><div class="ctx-item">Business Criticality</div><div class="ctx-val">{criticality}</div></div>
    <div><div class="ctx-item">Internet Exposure</div><div class="ctx-val">{exposure}</div></div>
    <div><div class="ctx-item">Total Components</div><div class="ctx-val">{analysis_result.get("total_components", 0)}</div></div>
  </div>

  <div class="summary-grid">
    <div class="gauge-wrap">{gauge_svg}</div>
    <div class="stat-box"><span class="stat-num" style="color:#ff2a5f">{critical_cnt}</span><span class="stat-label">Critical</span></div>
    <div class="stat-box"><span class="stat-num" style="color:#ff7a00">{high_cnt}</span><span class="stat-label">High</span></div>
    <div class="stat-box"><span class="stat-num" style="color:#ffc700">{medium_cnt}</span><span class="stat-label">Medium</span></div>
    <div class="stat-box"><span class="stat-num" style="color:#00e676">{low_cnt}</span><span class="stat-label">Low</span></div>
  </div>

  <div class="section-title">📋 Prioritized Vulnerability Action List ({total_vulns} Total)</div>
  <table>
    <thead><tr>
      <th>#</th><th>Risk Score</th><th>CVE ID</th><th>Component</th>
      <th>Tier</th><th>CVSS</th><th>Exploit</th><th>Remediation Action</th><th>Urgency</th>
    </tr></thead>
    <tbody>{rows_html}</tbody>
  </table>

  <div class="footer">
    Generated by Cyber Risk Prioritization Platform · SBOM Intelligence & Contextual Risk Scoring ·
    Score Formula: CVSS (40%) + Internet Exposure (25%) + Business Criticality (20%) + Exploit (10%) + Dependency (5%)
  </div>
</body>
</html>"""
    return html
