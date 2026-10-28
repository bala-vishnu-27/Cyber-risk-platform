# 🛡️ Cyber Risk Prioritization Platform (CRPP)

> **Context-Aware Software Bill of Materials (SBOM) Vulnerability Prioritization & Autonomous Threat Intelligence Engine**

[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-blueviolet?style=for-the-badge)](https://sarifweb.azurewebsites.net/)
[![EPSS Enabled](https://img.shields.io/badge/EPSS-Real--Time-00f2fe?style=for-the-badge)](https://www.first.org/epss/)

---

## 🌟 Executive Summary

Traditional vulnerability management floods security teams with hundreds of uncontextualized CVE alerts. **Cyber Risk Prioritization Platform (CRPP)** solves alert fatigue by synthesizing **Software Bill of Materials (SBOM)**, **Universal Vulnerability Feeds**, and **Business Context** to compute an actionable, mathematically weighted **0–100 Cyber Risk Score**.

CRPP features a **Universal Multi-Format Ingestion Engine** that seamlessly accepts vulnerability reports from Qualys, Nessus, GitHub CodeQL SARIF, Trivy, Grype, and Snyk, alongside dependency manifests in Python, Node.js, Java, and Go.

---

## 🚀 Key Features

### 1. 🌐 Universal Multi-Format Vulnerability Ingestion
Accepts any security report format without configuration:
- **CSV / Excel Spreadsheets** (Qualys, Nessus, Tenable, Jira exports, pen-test findings)
- **OASIS SARIF 2.1.0** (GitHub CodeQL, Microsoft, Snyk SARIF)
- **Container / App Scanners** (Aquasecurity Trivy JSON, Anchore Grype JSON, Snyk CLI JSON)
- **CycloneDX VEX XML & JSON** (Vulnerability Exploitability eXchange)
- **Plain Text CVE Lists** (Auto-extracts `CVE-YYYY-NNNNN`)

### 2. 🪄 Autonomous "Zero-Vuln-File" Threat Intelligence
- Upload **only** an SBOM manifest (`requirements.txt`, `package.json`, `pom.xml`, `go.mod`).
- The platform automatically scans your components against an enterprise threat intelligence database of **500+ CVEs** and live NVD/EPSS feeds.

### 3. 🎯 Multi-Factor Risk Scoring Algorithm
Calculates risk using 6 contextual weighted factors:
$$\text{Risk Score} = (0.35 \times \text{CVSS}) + (0.05 \times \text{EPSS}) + (0.25 \times \text{Exposure}) + (0.20 \times \text{Criticality}) + (0.10 \times \text{Exploit}) + (0.05 \times \text{Dep})$$

### 4. 🛠️ Actionable Remediation & SLA Deadlines
- Per-vulnerability upgrade guidance with exact shell commands (`pip`, `npm`, `mvn`).
- Dynamic SLA deadline calculations based on severity tier.
- Interactive risk acceptance and false-positive tracking.

### 5. 🔄 Enterprise Integrations & Dual-Way Export
- **One-Click Export**: SARIF 2.1.0, CSV spreadsheet, JSON.
- **CI/CD Scan Endpoint**: Ready for GitHub Actions, GitLab CI, and Jenkins.
- **Scan Comparison & History**: Compare multiple versions to evaluate security drift over time.

---

## 📁 Repository Structure

```text
cyber_risk_platform/
├── backend/
│   ├── app.py                  # High-performance HTTP API Server
│   ├── vuln_parser.py          # Universal Multi-Format Vulnerability Ingestor
│   ├── sbom_parser.py          # Multi-language SBOM & Manifest Parser
│   ├── vuln_matcher.py         # Component & CVE Correlation Engine
│   ├── risk_engine.py          # 6-Factor Mathematical Risk Scoring
│   ├── remediator.py           # Automated Patch & Remediation Generator
│   ├── sarif_exporter.py       # OASIS SARIF 2.1.0 Exporter
│   ├── nvd_fetcher.py          # Live NVD API & EPSS Threat Intel Fetcher
│   └── scan_history.py         # SQLite Persistence & Comparison Engine
├── frontend/
│   ├── index.html              # Cyberpunk Glassmorphic Dashboard
│   ├── app.js                  # Dynamic Interactive Controller
│   ├── styles.css              # Custom High-End Cyber Design System
│   └── poster.html             # Project Exhibition Poster
├── data/
│   ├── sample_qualys_report.csv    # Real Qualys/Nessus CSV export
│   ├── sample_github_codeql.sarif  # Real GitHub CodeQL SARIF report
│   ├── sample_trivy_scan.json      # Real Trivy container scanner output
│   ├── sample_requirements.txt     # Real Python dependency manifest
│   ├── real_sbom_large.json        # 25 Enterprise Dependencies
│   └── real_vulnerabilities_500.json # 500-CVE Reference Threat DB
├── run.py                      # One-click Launcher
├── start.bat                   # Windows Double-Click Launcher
└── package.json                # Optional npm start support
```

---

## ⚡ Quick Start

### Prerequisites
- Python 3.9 or higher (standard library only; no heavy external frameworks required!)
- Any modern web browser (Chrome, Edge, Firefox)

### Run Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/cyber_risk_platform.git
   cd cyber_risk_platform
   ```

2. **Start the Platform:**
   ```bash
   python run.py
   # or double-click start.bat (Windows)
   # or npm start
   ```

3. **Open in Browser:**
   Visit `http://127.0.0.1:8000`

---

## 🧪 Testing with Sample Files

Drag and drop any of the sample files located in `data/` directly into the UI:
- **Card 2 (SBOM)**: Drag `data/sample_requirements.txt` or `data/real_sbom_large.json`.
- **Card 3 (Vulnerabilities)**: Drag `data/sample_qualys_report.csv`, `data/sample_github_codeql.sarif`, or `data/sample_trivy_scan.json`.

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
