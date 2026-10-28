/**
 * Cyber Risk Prioritization Platform Frontend Controller
 */

// Global Application State
const appState = {
  appName: "E-Commerce Payment Gateway App",
  businessCriticality: "High",
  internetExposure: "High",
  appType: "Web Application",
  sbomMode: "upload", // Strictly File Upload
  selectedSbomId: null,
  sbomContent: null,
  vulnContent: null,
  analysisResults: null,
  activeFilter: "ALL",
  currentPage: 1,
  perPage: 25,
  heatmapFilter: null,
  theme: localStorage.getItem("cyber_risk_theme") || "dark",
  annotations: {} // cve_id -> { status, assignee, note }
};

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initEventListeners();
});

function initTheme() {
  document.documentElement.setAttribute("data-theme", appState.theme);
  updateThemeUI();
}

function toggleTheme() {
  appState.theme = appState.theme === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", appState.theme);
  localStorage.setItem("cyber_risk_theme", appState.theme);
  updateThemeUI();
}

function updateThemeUI() {
  const btnTheme = document.getElementById("btnThemeToggle");
  if (!btnTheme) return;
  if (appState.theme === "light") {
    btnTheme.querySelector("i").className = "fa-solid fa-moon";
    const lbl = document.getElementById("themeToggleText");
    if (lbl) lbl.innerText = "Dark";
  } else {
    btnTheme.querySelector("i").className = "fa-solid fa-sun";
    const lbl = document.getElementById("themeToggleText");
    if (lbl) lbl.innerText = "Light";
  }
}

function initEventListeners() {
  // Theme Toggle Button
  const btnTheme = document.getElementById("btnThemeToggle");
  if (btnTheme) btnTheme.addEventListener("click", toggleTheme);

  // Enterprise Feature Buttons
  const btnHistory = document.getElementById("btnScanHistory");
  if (btnHistory) btnHistory.addEventListener("click", openHistoryDrawer);

  const btnCompare = document.getElementById("btnCompareScans");
  if (btnCompare) btnCompare.addEventListener("click", openCompareModal);

  const btnCicd = document.getElementById("btnCicdIntegration");
  if (btnCicd) btnCicd.addEventListener("click", () => document.getElementById("modalCicd").classList.remove("hidden"));

  // Modal Closers
  document.getElementById("btnCloseHistory").addEventListener("click", () => document.getElementById("drawerHistory").classList.add("hidden"));
  document.getElementById("btnCloseCompare").addEventListener("click", () => document.getElementById("modalCompare").classList.add("hidden"));
  document.getElementById("btnCloseCicd").addEventListener("click", () => document.getElementById("modalCicd").classList.add("hidden"));

  const btnExecuteComp = document.getElementById("btnExecuteCompare");
  if (btnExecuteComp) btnExecuteComp.addEventListener("click", executeScanComparison);

  const btnSimWebhook = document.getElementById("btnSimulateWebhook");
  if (btnSimWebhook) {
    btnSimWebhook.addEventListener("click", () => {
      alert("🔔 Webhook Alert Triggered! Notification sent to PagerDuty & Slack security channel.");
    });
  }

  // Navigation & Demo buttons
  document.getElementById("btnLoadDemo").addEventListener("click", () => loadDemoData(false));
  const btnLarge = document.getElementById("btnLoadLargeDemo");
  if (btnLarge) btnLarge.addEventListener("click", () => loadDemoData(true));

  document.getElementById("btnStartAnalysis").addEventListener("click", startAnalysisPipeline);
  document.getElementById("btnNewAnalysis").addEventListener("click", () => switchScreen(1));

  // Clear Heatmap Filter Button
  const btnClearHeatmap = document.getElementById("btnClearHeatmapFilter");
  if (btnClearHeatmap) {
    btnClearHeatmap.addEventListener("click", () => {
      appState.heatmapFilter = null;
      btnClearHeatmap.classList.add("hidden");
      renderRiskHeatmap();
      appState.currentPage = 1;
      renderRiskTable();
    });
  }

  // File Drop Zones Setup (Upload only)
  setupDropZone("sbomDropZone", "fileSbom", handleSbomFiles);
  setupDropZone("vulnDropZone", "fileVuln", handleVulnFiles);

  // Severity Filters & Search
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      e.target.classList.add("active");
      appState.activeFilter = e.target.dataset.filter;
      appState.currentPage = 1;
      renderRiskTable();
    });
  });

  // Sev Box Filter clicks in overview card
  document.querySelectorAll(".sev-box").forEach(box => {
    box.style.cursor = "pointer";
    box.addEventListener("click", () => {
      const filter = box.dataset.filter;
      if (filter) {
        // Toggle filter-active visual state on sev-box cards
        const currentlyActive = box.classList.contains("filter-active");
        document.querySelectorAll(".sev-box").forEach(b => b.classList.remove("filter-active"));
        if (!currentlyActive) box.classList.add("filter-active");

        // Sync with filter buttons
        document.querySelectorAll(".filter-btn").forEach(b => {
          if (b.dataset.filter === filter && !currentlyActive) b.click();
          else if (b.dataset.filter === "ALL" && currentlyActive) b.click();
        });
      }
    });
  });

  document.getElementById("inputSearch").addEventListener("input", () => {
    appState.currentPage = 1;
    renderRiskTable();
  });

  // Per Page Selector
  const selectPerPage = document.getElementById("selectPerPage");
  if (selectPerPage) {
    selectPerPage.addEventListener("change", (e) => {
      const val = e.target.value;
      appState.perPage = val === "ALL" ? 999999 : parseInt(val);
      appState.currentPage = 1;
      renderRiskTable();
    });
  }

  // Export Buttons
  document.getElementById("btnExportCSV").addEventListener("click", exportCSV);
  document.getElementById("btnExportJSON").addEventListener("click", exportJSON);
  const btnSarif = document.getElementById("btnExportSARIF");
  if (btnSarif) btnSarif.addEventListener("click", exportSARIF);

  // Modal Close
  document.getElementById("btnCloseModal").addEventListener("click", closeModal);
}

function switchScreen(stepNum) {
  // Update Nav header
  document.querySelectorAll(".nav-step").forEach((el, index) => {
    if (index + 1 === stepNum) el.classList.add("active");
    else el.classList.remove("active");
  });

  // Update Screen Section
  document.querySelectorAll(".screen-section").forEach(sec => sec.classList.remove("active"));

  if (stepNum === 1) document.getElementById("screenInput").classList.add("active");
  else if (stepNum === 2) document.getElementById("screenProcessing").classList.add("active");
  else if (stepNum === 3) document.getElementById("screenDashboard").classList.add("active");
}

function setupDropZone(dropZoneId, fileInputId, handleFilesFn) {
  const dropZone = document.getElementById(dropZoneId);
  const fileInput = document.getElementById(fileInputId);

  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("hover");
  });

  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("hover"));

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("hover");
    if (e.dataTransfer.files.length > 0) {
      handleFilesFn(e.dataTransfer.files);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleFilesFn(e.target.files);
    }
  });
}

async function handleSbomFiles(files) {
  const fileList = Array.from(files);
  let allComponents = [];
  let detectedFmt = "CycloneDX / SPDX";

  for (const file of fileList) {
    try {
      const text = await file.text();
      // Send to backend universal SBOM parser
      const resp = await fetch("/api/sbom/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: file.name, content: text })
      });
      const data = await resp.json();
      if (data.components && data.components.length > 0) {
        allComponents = allComponents.concat(data.components);
      } else {
        // Fallback: client-side JSON parsing
        try {
          const json = JSON.parse(text);
          if (json.components) allComponents = allComponents.concat(json.components);
          else if (json.packages) allComponents = allComponents.concat(json.packages);
          else if (Array.isArray(json)) allComponents = allComponents.concat(json);
        } catch (_) {}
      }

      // Infer format from filename
      const fname = file.name.toLowerCase();
      if (fname.includes("requirements")) detectedFmt = "Python requirements.txt";
      else if (fname.includes("package-lock")) detectedFmt = "npm package-lock.json";
      else if (fname.includes("package.json")) detectedFmt = "Node.js package.json";
      else if (fname.includes("pom.xml")) detectedFmt = "Maven POM XML";
      else if (fname.includes("go.mod")) detectedFmt = "Go Modules";
      else if (fname.endsWith(".csv")) detectedFmt = "CSV Component List";
      else if (text.includes("CycloneDX") || text.includes("bomFormat")) detectedFmt = "CycloneDX JSON";
      else if (text.includes("SPDXID") || text.includes("spdxVersion")) detectedFmt = "SPDX JSON";
    } catch (err) {
      console.warn("SBOM file parse warning:", err);
    }
  }

  appState.sbomContent = { components: allComponents };
  appState.sbomDetectedFormat = detectedFmt;

  const label = fileList.length === 1 ? fileList[0].name : `${fileList.length} SBOM Files`;
  document.getElementById("nameSbom").innerText = label;
  document.getElementById("countSbom").innerText = `${allComponents.length} Components`;
  const fmtEl = document.getElementById("formatSbom");
  if (fmtEl) fmtEl.innerText = detectedFmt;
  document.getElementById("statusSbom").classList.remove("hidden");

  updateAutonomousModeUI();
}

async function handleVulnFiles(files) {
  const fileList = Array.from(files);
  let allVulns = [];
  let detectedFmt = "Universal Feed";

  for (const file of fileList) {
    try {
      const text = await file.text();
      // Send to Universal Vulnerability Ingestor API
      const resp = await fetch("/api/vuln/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: file.name, content: text })
      });
      const data = await resp.json();
      if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        allVulns = allVulns.concat(data.vulnerabilities);
        if (data.detected_format) detectedFmt = data.detected_format;
      } else {
        // Fallback: client-side JSON try
        try {
          const json = JSON.parse(text);
          if (json.vulnerabilities) allVulns = allVulns.concat(json.vulnerabilities);
          else if (Array.isArray(json)) allVulns = allVulns.concat(json);
        } catch (_) {}
      }
    } catch (err) {
      console.warn("Vuln file parse warning:", err);
    }
  }

  appState.vulnContent = { vulnerabilities: allVulns };
  appState.vulnDetectedFormat = detectedFmt;

  const label = fileList.length === 1 ? fileList[0].name : `${fileList.length} Vuln Files`;
  document.getElementById("nameVuln").innerText = label;
  document.getElementById("countVuln").innerText = `${allVulns.length} Findings`;
  const fmtEl = document.getElementById("formatVuln");
  if (fmtEl) fmtEl.innerText = detectedFmt;
  document.getElementById("statusVuln").classList.remove("hidden");

  updateAutonomousModeUI();
}

function updateAutonomousModeUI() {
  const banner = document.getElementById("autonomousBanner");
  const title = document.getElementById("autonomousBannerTitle");
  const desc = document.getElementById("autonomousBannerDesc");
  if (!banner) return;

  const hasSbom = appState.sbomContent && appState.sbomContent.components && appState.sbomContent.components.length > 0;
  const hasVuln = appState.vulnContent && appState.vulnContent.vulnerabilities && appState.vulnContent.vulnerabilities.length > 0;

  if (hasSbom && !hasVuln) {
    banner.classList.remove("hidden");
    if (title) title.innerText = "Autonomous Threat Intelligence Mode Active";
    if (desc) desc.innerText = `SBOM uploaded (${appState.sbomDetectedFormat || "Dependencies"}). The platform will automatically cross-match your components against live NVD and 500+ enterprise CVE threat databases!`;
  } else if (hasVuln && !hasSbom) {
    banner.classList.remove("hidden");
    if (title) title.innerText = "Standalone Security Ingestion Active";
    if (desc) desc.innerText = `Ingested findings from ${appState.vulnDetectedFormat || "Security Report"}. Component hierarchy will be automatically derived from findings!`;
  } else {
    banner.classList.add("hidden");
  }
}


async function loadDemoData(isLarge = false) {
  try {
    const endpoint = isLarge ? "/api/sample-large-data" : "/api/sample-data";
    const resp = await fetch(endpoint);
    const data = await resp.json();

    appState.appName = data.app_name;
    appState.businessCriticality = data.business_criticality;
    appState.internetExposure = data.internet_exposure;
    appState.appType = data.app_type;
    appState.sbomContent = data.sbom_content;
    appState.vulnContent = data.vuln_content;
    appState.sbomDetectedFormat = "CycloneDX 1.5 JSON";
    appState.vulnDetectedFormat = isLarge ? "500-CVE Database" : "Standard CVE Report";

    document.getElementById("appName").value = data.app_name;
    document.getElementById("businessCriticality").value = data.business_criticality;
    document.getElementById("internetExposure").value = data.internet_exposure;
    document.getElementById("appType").value = data.app_type;

    const sbomCount = data.sbom_content.components ? data.sbom_content.components.length : 0;
    const vulnCount = data.vuln_content.vulnerabilities ? data.vuln_content.vulnerabilities.length : 0;

    document.getElementById("nameSbom").innerText = isLarge ? "real_sbom_large.json" : "sample_sbom.json";
    document.getElementById("countSbom").innerText = `${sbomCount} Components`;
    const fmtSbom = document.getElementById("formatSbom");
    if (fmtSbom) fmtSbom.innerText = "CycloneDX JSON";
    document.getElementById("statusSbom").classList.remove("hidden");

    document.getElementById("nameVuln").innerText = isLarge ? "real_vulnerabilities_500.json" : "sample_vulns.json";
    document.getElementById("countVuln").innerText = `${vulnCount} Vulnerabilities`;
    const fmtVuln = document.getElementById("formatVuln");
    if (fmtVuln) fmtVuln.innerText = isLarge ? "500-CVE DB" : "Standard JSON";
    document.getElementById("statusVuln").classList.remove("hidden");

    updateAutonomousModeUI();
  } catch (err) {
    alert("Could not load demo sample data: " + err.message);
  }
}

async function startAnalysisPipeline() {
  appState.appName = document.getElementById("appName").value || "Production System";
  appState.businessCriticality = document.getElementById("businessCriticality").value;
  appState.internetExposure = document.getElementById("internetExposure").value;
  appState.appType = document.getElementById("appType").value;

  const hasSbom = appState.sbomContent && appState.sbomContent.components && appState.sbomContent.components.length > 0;
  const hasVuln = appState.vulnContent && appState.vulnContent.vulnerabilities && appState.vulnContent.vulnerabilities.length > 0;

  if (!hasSbom && !hasVuln) {
    alert("Please upload at least an SBOM file or a Vulnerability report file to begin analysis!");
    return;
  }

  // Reset filter states
  appState.activeFilter = "ALL";
  appState.heatmapFilter = null;
  appState.currentPage = 1;
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
  document.querySelector(".filter-btn[data-filter='ALL']").classList.add("active");

  // Switch to Processing Screen
  switchScreen(2);
  runProcessingAnimations();

  try {
    const payload = {
      app_name: appState.appName,
      business_criticality: appState.businessCriticality,
      internet_exposure: appState.internetExposure,
      app_type: appState.appType,
      sbom_content: appState.sbomContent,
      vuln_content: appState.vulnContent
    };

    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const results = await response.json();
    if (results.error) {
      alert("Analysis Notice: " + results.error);
      switchScreen(1);
      return;
    }

    appState.analysisResults = results;

    // Fetch existing annotations if scan_id exists
    if (results.scan_id) {
      fetchAnnotations(results.scan_id);
    }

    // Show skeleton UI transition briefly before full dashboard display
    setTimeout(() => {
      switchScreen(3);
      showSkeletonLoading();
      setTimeout(() => {
        hideSkeletonLoading();
        renderDashboard();
      }, 500);
    }, 3200);

  } catch (err) {
    alert("Server Communication Error: " + err.message);
    switchScreen(1);
  }
}

function showSkeletonLoading() {
  const sk = document.getElementById("skeletonDashboard");
  const rd = document.getElementById("realDashboard");
  if (sk) sk.classList.remove("hidden");
  if (rd) rd.classList.remove("hidden");
}

function hideSkeletonLoading() {
  const sk = document.getElementById("skeletonDashboard");
  const rd = document.getElementById("realDashboard");
  if (sk) sk.classList.add("hidden");
  if (rd) rd.classList.remove("hidden");
}

function runProcessingAnimations() {
  const logsEl = document.getElementById("terminalLogs");
  logsEl.innerHTML = "";

  const sbomFmt = appState.sbomDetectedFormat || "Dependency List";
  const vulnFmt = appState.vulnDetectedFormat || "Threat Intelligence Feed";

  const steps = [
    { id: "pstep1", msg: `[STEP 1] Universal Ingestor: Ingested ${sbomFmt}... extracted component hierarchy.`, delay: 400 },
    { id: "pstep2", msg: "[STEP 2] Component Normalization: Standardizing Package URLs (purl) & version identifiers.", delay: 900 },
    { id: "pstep3", msg: `[STEP 3] Vulnerability Ingestion & Matching: Ingested ${vulnFmt}... cross-matching CVE database.`, delay: 1400 },
    { id: "pstep4", msg: "[STEP 4] Multi-Factor Risk Scoring: Executing contextual formula (CVSS 35%, EPSS 5%, Exposure 25%, Criticality 20%, Exploit 10%, Dep 5%).", delay: 2000 },
    { id: "pstep5", msg: "[STEP 5] Prioritization Engine: Sorting vulnerabilities from highest calculated impact to lowest.", delay: 2500 },
    { id: "pstep6", msg: "[STEP 6] Remediation Recommender: Generating fix patches, upgrade commands & SLA deadlines.", delay: 3000 }
  ];

  steps.forEach(st => {
    setTimeout(() => {
      document.querySelectorAll(".pipeline-step").forEach(el => el.classList.remove("active"));
      const currentStepEl = document.getElementById(st.id);
      if (currentStepEl) {
        currentStepEl.classList.add("active");
        currentStepEl.classList.add("completed");
      }

      const now = new Date().toLocaleTimeString();
      const logLine = document.createElement("div");
      logLine.className = "log-line";
      logLine.innerHTML = `<span class="log-time">[${now}]</span> <span class="log-info">${st.msg}</span>`;
      logsEl.appendChild(logLine);
      logsEl.scrollTop = logsEl.scrollHeight;
    }, st.delay);
  });
}

function renderDashboard() {
  const data = appState.analysisResults;
  const summary = data.risk_summary;

  // App Header Info
  document.getElementById("dashAppName").innerText = data.application.app_name;
  document.getElementById("dashAppType").innerHTML = `<i class="fa-solid fa-layer-group"></i> ${data.application.app_type}`;
  document.getElementById("dashAppExposure").innerHTML = `<i class="fa-solid fa-globe"></i> ${data.application.internet_exposure} Exposure`;
  document.getElementById("dashAppCriticality").innerHTML = `<i class="fa-solid fa-building-columns"></i> ${data.application.business_criticality} Criticality`;

  // Threshold Risk Alert Evaluation
  evaluateRiskThresholdAlert(summary.overall_app_score, summary.critical_count);

  // Render SVG Speedometer Radial Gauge
  renderScoreGauge(summary.overall_app_score, summary.overall_tier);

  // Counts
  document.getElementById("cntCritical").innerText = summary.critical_count;
  document.getElementById("cntHigh").innerText = summary.high_count;
  document.getElementById("cntMedium").innerText = summary.medium_count;
  document.getElementById("cntLow").innerText = summary.low_count;

  // Render Visual Analytics
  renderRiskHeatmap();
  renderSeverityTrendChart();

  // Render Table with Pagination
  renderRiskTable();
}

function evaluateRiskThresholdAlert(score, criticalCount) {
  const alertBanner = document.getElementById("thresholdAlertBanner");
  const alertTitle = document.getElementById("alertBannerTitle");
  const alertDesc = document.getElementById("alertBannerDesc");
  if (!alertBanner) return;

  if (score > 80 || criticalCount > 0) {
    alertBanner.classList.remove("hidden");
    alertTitle.innerText = `🚨 CRITICAL RISK THRESHOLD EXCEEDED (Score: ${score}/100)`;
    alertDesc.innerText = `Application score has breached safety thresholds (${criticalCount} Critical vulnerabilities detected). Immediate patch deployment required!`;
  } else {
    alertBanner.classList.add("hidden");
  }
}

function renderScoreGauge(score, tier) {
  const scoreValEl = document.getElementById("dashScoreValue");
  const arcEl = document.getElementById("scoreGaugeArc");
  const tierBadge = document.getElementById("dashScoreTier");

  // Circle radius 54 -> Circumference 339.29
  const circumference = 339.29;
  const offset = circumference - (circumference * (score / 100));

  if (arcEl) {
    arcEl.style.strokeDashoffset = offset;
    const gradId = tier === "CRITICAL" ? "gaugeGradCritical" :
                   tier === "HIGH" ? "gaugeGradHigh" :
                   tier === "MEDIUM" ? "gaugeGradMedium" : "gaugeGradLow";
    arcEl.style.stroke = `url(#${gradId})`;
  }

  if (tierBadge) {
    tierBadge.innerText = tier + " RISK";
    tierBadge.className = "score-tier-badge badge-" + (tier === "CRITICAL" ? "danger" : tier === "HIGH" ? "warning" : "success");
  }

  // Smooth Counter Animation
  let start = 0;
  const duration = 900;
  const stepTime = 16;
  const totalSteps = duration / stepTime;
  const stepVal = score / totalSteps;

  const counterTimer = setInterval(() => {
    start += stepVal;
    if (start >= score) {
      scoreValEl.innerText = Math.round(score);
      clearInterval(counterTimer);
    } else {
      scoreValEl.innerText = Math.round(start);
    }
  }, stepTime);
}

function getComponentCategory(compName) {
  const c = compName.toLowerCase();
  if (c.includes("django") || c.includes("express") || c.includes("spring") || c.includes("flask") || c.includes("react") || c.includes("vue") || c.includes("angular") || c.includes("struts") || c.includes("fastapi")) {
    return "Web Frameworks";
  }
  if (c.includes("sql") || c.includes("mongo") || c.includes("redis") || c.includes("postgres") || c.includes("driver") || c.includes("db") || c.includes("orm") || c.includes("hibernate") || c.includes("psycopg")) {
    return "Database & Storage";
  }
  if (c.includes("jwt") || c.includes("auth") || c.includes("crypto") || c.includes("ssl") || c.includes("tls") || c.includes("oauth") || c.includes("sec") || c.includes("key") || c.includes("token")) {
    return "Auth & Crypto";
  }
  if (c.includes("xml") || c.includes("json") || c.includes("net") || c.includes("http") || c.includes("axios") || c.includes("request") || c.includes("parser") || c.includes("curl") || c.includes("log") || c.includes("yaml")) {
    return "Network & Parsing";
  }
  return "Utility Libraries";
}

function renderRiskHeatmap() {
  const container = document.getElementById("riskHeatmap");
  if (!container || !appState.analysisResults) return;

  const items = appState.analysisResults.remediations;
  const categories = ["Web Frameworks", "Database & Storage", "Auth & Crypto", "Network & Parsing", "Utility Libraries"];
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  const matrix = {};
  categories.forEach(cat => {
    matrix[cat] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  });

  items.forEach(item => {
    const cat = getComponentCategory(item.component);
    const sev = item.risk_tier;
    if (matrix[cat] && matrix[cat][sev] !== undefined) {
      matrix[cat][sev]++;
    }
  });

  let html = `<table class="heatmap-table"><thead><tr><th>Severity</th>`;
  categories.forEach(cat => {
    html += `<th>${cat}</th>`;
  });
  html += `</tr></thead><tbody>`;

  severities.forEach(sev => {
    html += `<tr><td class="row-label">${sev}</td>`;
    categories.forEach(cat => {
      const count = matrix[cat][sev];
      let heatClass = "heat-0";
      if (count > 0) {
        if (sev === "CRITICAL") heatClass = "heat-crit";
        else if (sev === "HIGH") heatClass = "heat-high";
        else if (sev === "MEDIUM") heatClass = "heat-med";
        else heatClass = "heat-low";
      }

      const isSelected = appState.heatmapFilter && appState.heatmapFilter.category === cat && appState.heatmapFilter.severity === sev;
      const activeClass = isSelected ? " active-filter" : "";

      html += `<td>
        <div class="heatmap-cell ${heatClass}${activeClass}" data-cat="${cat}" data-sev="${sev}" title="${cat} - ${sev}: ${count} vulnerabilities">
          ${count}
        </div>
      </td>`;
    });
    html += `</tr>`;
  });
  html += `</tbody></table>`;

  container.innerHTML = html;

  container.querySelectorAll(".heatmap-cell").forEach(cell => {
    cell.addEventListener("click", () => {
      const cat = cell.dataset.cat;
      const sev = cell.dataset.sev;

      if (appState.heatmapFilter && appState.heatmapFilter.category === cat && appState.heatmapFilter.severity === sev) {
        appState.heatmapFilter = null;
      } else {
        appState.heatmapFilter = { category: cat, severity: sev };
      }

      const btnClear = document.getElementById("btnClearHeatmapFilter");
      if (btnClear) {
        if (appState.heatmapFilter) {
          btnClear.classList.remove("hidden");
          btnClear.innerHTML = `<i class="fa-solid fa-xmark"></i> Clear Filter (${cat} - ${sev})`;
        } else {
          btnClear.classList.add("hidden");
        }
      }

      renderRiskHeatmap();
      appState.currentPage = 1;
      renderRiskTable();
    });
  });
}

function renderSeverityTrendChart() {
  const container = document.getElementById("severityTrendChart");
  if (!container || !appState.analysisResults) return;

  const summary = appState.analysisResults.risk_summary;
  const total = summary.total_vulnerabilities || 1;

  const tiers = [
    { key: "CRITICAL", label: "Critical Severity", count: summary.critical_count, fillClass: "sev-critical" },
    { key: "HIGH", label: "High Severity", count: summary.high_count, fillClass: "sev-high" },
    { key: "MEDIUM", label: "Medium Severity", count: summary.medium_count, fillClass: "sev-medium" },
    { key: "LOW", label: "Low Severity", count: summary.low_count, fillClass: "sev-low" }
  ];

  let html = "";
  tiers.forEach(t => {
    const pct = Math.round((t.count / total) * 100) || (t.count > 0 ? 1 : 0);
    html += `
      <div class="chart-bar-row">
        <div class="chart-bar-header">
          <span><i class="fa-solid fa-square" style="font-size:10px; color: var(--sev-${t.key.toLowerCase()}); margin-right:6px;"></i>${t.label}</span>
          <span>${t.count} vulns (${pct}%)</span>
        </div>
        <div class="chart-bar-track">
          <div class="chart-bar-fill ${t.fillClass}" style="width: ${pct}%;"></div>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

function renderRiskTable() {
  const tbody = document.getElementById("tableRiskBody");
  tbody.innerHTML = "";

  if (!appState.analysisResults) return;

  let list = appState.analysisResults.remediations;
  const searchQuery = document.getElementById("inputSearch").value.toLowerCase().trim();

  // 1. Severity Filter
  if (appState.activeFilter !== "ALL") {
    list = list.filter(item => item.risk_tier === appState.activeFilter);
  }

  // 2. Heatmap Matrix Cell Filter
  if (appState.heatmapFilter) {
    list = list.filter(item => {
      const catMatches = getComponentCategory(item.component) === appState.heatmapFilter.category;
      const sevMatches = item.risk_tier === appState.heatmapFilter.severity;
      return catMatches && sevMatches;
    });
  }

  // 3. Search Filter
  if (searchQuery) {
    list = list.filter(item =>
      item.component.toLowerCase().includes(searchQuery) ||
      item.cve_id.toLowerCase().includes(searchQuery) ||
      item.description.toLowerCase().includes(searchQuery)
    );
  }

  const totalRecords = list.length;

  if (totalRecords === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No vulnerabilities matched the search / filter criteria.</td></tr>`;
    renderPaginationControls(0, 0, 0);
    return;
  }

  // Pagination calculation
  const totalPages = Math.ceil(totalRecords / appState.perPage);
  if (appState.currentPage > totalPages) appState.currentPage = totalPages;
  if (appState.currentPage < 1) appState.currentPage = 1;

  const startIndex = (appState.currentPage - 1) * appState.perPage;
  const endIndex = Math.min(startIndex + appState.perPage, totalRecords);
  const pagedList = list.slice(startIndex, endIndex);

  pagedList.forEach((item, pIndex) => {
    const globalRank = startIndex + pIndex + 1;
    const originalIndex = appState.analysisResults.remediations.findIndex(x => x.cve_id === item.cve_id && x.component === item.component);
    
    // Annotation Status
    const annKey = `${item.cve_id}_${item.component}`;
    const ann = appState.annotations[annKey] || { status: "OPEN" };
    
    let rowClass = "";
    if (ann.status === "ACCEPTED RISK") rowClass = "row-accepted-risk";
    else if (ann.status === "FALSE POSITIVE") rowClass = "row-false-positive";

    const tr = document.createElement("tr");
    let baseRowClass = `sev-row-${item.risk_tier.toLowerCase()}`;
    if (rowClass) baseRowClass += ` ${rowClass}`;
    tr.className = baseRowClass;

    let rankBadgeHtml = `<span class="rank-badge-pill">#${globalRank}</span>`;
    if (globalRank === 1) {
      rankBadgeHtml = `<span class="rank-badge-pill rank-badge-1"><i class="fa-solid fa-crown"></i> #1</span>`;
    } else if (globalRank === 2) {
      rankBadgeHtml = `<span class="rank-badge-pill rank-badge-2">#2</span>`;
    } else if (globalRank === 3) {
      rankBadgeHtml = `<span class="rank-badge-pill rank-badge-3">#3</span>`;
    }

    tr.innerHTML = `
      <td>${rankBadgeHtml}</td>
      <td>
        <span class="score-badge-pill ${item.risk_tier}">${item.risk_score} <small>/100</small></span>
      </td>
      <td class="cve-pill-cell">
        <div class="cve-id-bold"><i class="fa-solid fa-bug text-danger"></i> ${item.cve_id}</div>
        <select class="status-pill-select" onchange="saveVulnerabilityAnnotation('${item.cve_id}', '${item.component}', this.value)">
          <option value="OPEN" ${ann.status === "OPEN" ? "selected" : ""}>🔴 Open</option>
          <option value="ACCEPTED RISK" ${ann.status === "ACCEPTED RISK" ? "selected" : ""}>🟡 Accepted Risk</option>
          <option value="FALSE POSITIVE" ${ann.status === "FALSE POSITIVE" ? "selected" : ""}>⚪ False Positive</option>
          <option value="IN PROGRESS" ${ann.status === "IN PROGRESS" ? "selected" : ""}>🔵 In Progress</option>
          <option value="RESOLVED" ${ann.status === "RESOLVED" ? "selected" : ""}>🟢 Resolved</option>
        </select>
      </td>
      <td>
        <div class="comp-name-bold"><i class="fa-solid fa-cube text-cyan"></i> ${item.component}</div>
        <div class="comp-ver-badge">v${item.current_version}</div>
      </td>
      <td><span class="badge badge-cvss ${item.cvss_score >= 8 ? 'badge-danger' : 'badge-warning'}"><i class="fa-solid fa-gauge-high"></i> ${item.cvss_score} CVSS</span></td>
      <td>
        ${item.exploit_available ? '<span class="badge badge-danger badge-glow"><i class="fa-solid fa-skull"></i> Exploit Available</span>' : '<span class="badge badge-info"><i class="fa-solid fa-shield"></i> Theoretical</span>'}
      </td>
      <td>
        <div class="remediation-text-bold"><i class="fa-solid fa-wrench text-warning"></i> ${item.remediation.primary_action}</div>
        <div class="cli-code-block"><code>${item.remediation.cli_command}</code></div>
      </td>
      <td style="text-align: center; white-space: nowrap;">
        <button class="btn-fix-action" onclick="showRemediationModal(${originalIndex >= 0 ? originalIndex : 0})" title="Click to view detailed remediation guide & patch steps">
          <i class="fa-solid fa-wand-magic-sparkles"></i> Full Details
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  renderPaginationControls(startIndex + 1, endIndex, totalRecords);
}

function renderPaginationControls(startItem, endItem, totalRecords) {
  const infoEl = document.getElementById("paginationInfo");
  const btnsEl = document.getElementById("paginationPageBtns");
  if (!infoEl || !btnsEl) return;

  if (totalRecords === 0) {
    infoEl.innerText = "Showing 0 of 0 vulnerabilities";
    btnsEl.innerHTML = "";
    return;
  }

  infoEl.innerText = `Showing ${startItem} to ${endItem} of ${totalRecords} vulnerabilities`;

  const totalPages = Math.ceil(totalRecords / appState.perPage);
  if (totalPages <= 1) {
    btnsEl.innerHTML = "";
    return;
  }

  let html = "";
  
  // Previous button
  html += `<button class="page-btn" ${appState.currentPage === 1 ? 'disabled' : ''} onclick="changePage(${appState.currentPage - 1})"><i class="fa-solid fa-chevron-left"></i></button>`;

  // Page Numbers
  const maxButtons = 5;
  let startPage = Math.max(1, appState.currentPage - 2);
  let endPage = Math.min(totalPages, startPage + maxButtons - 1);
  if (endPage - startPage < maxButtons - 1) {
    startPage = Math.max(1, endPage - maxButtons + 1);
  }

  if (startPage > 1) {
    html += `<button class="page-btn" onclick="changePage(1)">1</button>`;
    if (startPage > 2) html += `<span style="color: var(--text-dark); padding: 0 4px;">...</span>`;
  }

  for (let p = startPage; p <= endPage; p++) {
    const activeClass = p === appState.currentPage ? " active" : "";
    html += `<button class="page-btn${activeClass}" onclick="changePage(${p})">${p}</button>`;
  }

  if (endPage < totalPages) {
    if (endPage < totalPages - 1) html += `<span style="color: var(--text-dark); padding: 0 4px;">...</span>`;
    html += `<button class="page-btn" onclick="changePage(${totalPages})">${totalPages}</button>`;
  }

  // Next button
  html += `<button class="page-btn" ${appState.currentPage === totalPages ? 'disabled' : ''} onclick="changePage(${appState.currentPage + 1})"><i class="fa-solid fa-chevron-right"></i></button>`;

  btnsEl.innerHTML = html;
}

function changePage(page) {
  appState.currentPage = page;
  renderRiskTable();
  const tableCard = document.querySelector(".table-card");
  if (tableCard) tableCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

// Enterprise Feature 6: Annotation Persistence
async function saveVulnerabilityAnnotation(cve_id, component, status) {
  const annKey = `${cve_id}_${component}`;
  appState.annotations[annKey] = { status };

  if (appState.analysisResults && appState.analysisResults.scan_id) {
    try {
      await fetch("/api/annotations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scan_id: appState.analysisResults.scan_id,
          cve_id: cve_id,
          component: component,
          status: status
        })
      });
    } catch (err) {
      console.warn("Could not save annotation to server:", err);
    }
  }

  renderRiskTable();
}

async function fetchAnnotations(scanId) {
  try {
    const resp = await fetch(`/api/annotations/${scanId}`);
    const list = await resp.json();
    if (Array.isArray(list)) {
      list.forEach(a => {
        appState.annotations[`${a.cve_id}_${a.component}`] = { status: a.status };
      });
    }
  } catch (err) {
    console.warn("Error fetching annotations:", err);
  }
}

// Enterprise Feature 1: History Drawer
async function openHistoryDrawer() {
  const drawer = document.getElementById("drawerHistory");
  const container = document.getElementById("historyListContainer");
  drawer.classList.remove("hidden");
  container.innerHTML = `<div style="text-align:center; padding: 20px; color: var(--text-muted);"><i class="fa-solid fa-spinner spinner-icon"></i> Loading history...</div>`;

  try {
    const resp = await fetch("/api/history?limit=20");
    const history = await resp.json();

    if (!Array.isArray(history) || history.length === 0) {
      container.innerHTML = `<div style="text-align:center; padding: 20px; color: var(--text-muted);">No scan history found. Run a scan to see records!</div>`;
      return;
    }

    let html = "";
    history.forEach(sc => {
      const tier = sc.overall_tier || "UNKNOWN";
      const tierClass = tier === "CRITICAL" ? "danger" : tier === "HIGH" ? "warning" : "success";

      html += `
        <div class="history-item" onclick="restoreScanFromHistory(${sc.id})">
          <div>
            <div class="history-app-name">${sc.app_name}</div>
            <div class="history-meta">
              <span><i class="fa-solid fa-calendar-days"></i> ${new Date(sc.scan_date).toLocaleString()}</span>
              <span><i class="fa-solid fa-bug"></i> ${sc.total_vulnerabilities} Vulns</span>
            </div>
          </div>
          <div class="history-score-badge badge-${tierClass}">
            Score: ${sc.overall_app_score}/100 (${tier})
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div style="text-align:center; padding: 20px; color: var(--sev-critical);">Failed to load history: ${err.message}</div>`;
  }
}

async function restoreScanFromHistory(scanId) {
  document.getElementById("drawerHistory").classList.add("hidden");
  showSkeletonLoading();
  switchScreen(3);

  try {
    const resp = await fetch(`/api/history/${scanId}`);
    const data = await resp.json();
    if (data.error) {
      alert("Error loading scan: " + data.error);
      hideSkeletonLoading();
      return;
    }

    appState.analysisResults = data;
    if (data.application) {
      appState.appName = data.application.app_name;
      appState.businessCriticality = data.application.business_criticality;
      appState.internetExposure = data.application.internet_exposure;
      appState.appType = data.application.app_type;
    }

    fetchAnnotations(scanId);

    setTimeout(() => {
      hideSkeletonLoading();
      renderDashboard();
    }, 400);
  } catch (err) {
    alert("Error fetching historical scan: " + err.message);
    hideSkeletonLoading();
  }
}

// Enterprise Feature 2: Multi-App Comparison
async function openCompareModal() {
  const modal = document.getElementById("modalCompare");
  const selectA = document.getElementById("selectScanA");
  const selectB = document.getElementById("selectScanB");
  modal.classList.remove("hidden");

  selectA.innerHTML = `<option>Loading scans...</option>`;
  selectB.innerHTML = `<option>Loading scans...</option>`;

  try {
    const resp = await fetch("/api/history?limit=30");
    const history = await resp.json();

    if (!Array.isArray(history) || history.length < 2) {
      alert("Please run at least 2 scans to compare multi-application risks!");
      modal.classList.add("hidden");
      return;
    }

    let opts = "";
    history.forEach(sc => {
      opts += `<option value="${sc.id}">${sc.app_name} (${new Date(sc.scan_date).toLocaleDateString()}) - Score: ${sc.overall_app_score}</option>`;
    });

    selectA.innerHTML = opts;
    selectB.innerHTML = opts;
    if (history.length > 1) selectB.selectedIndex = 1;

  } catch (err) {
    alert("Error loading scan options for comparison: " + err.message);
  }
}

async function executeScanComparison() {
  const scanA = document.getElementById("selectScanA").value;
  const scanB = document.getElementById("selectScanB").value;
  const container = document.getElementById("compareResultsContainer");

  container.innerHTML = `<div style="text-align:center; padding: 20px; color: var(--text-muted);"><i class="fa-solid fa-spinner spinner-icon"></i> Computing comparison matrix...</div>`;

  try {
    const resp = await fetch(`/api/compare?scan_a=${scanA}&scan_b=${scanB}`);
    const comp = await resp.json();

    if (comp.error) {
      container.innerHTML = `<div style="color: var(--sev-critical); text-align:center;">${comp.error}</div>`;
      return;
    }

    const diff = comp.score_difference;
    const isBMoreRisky = comp.scan_b.overall_app_score > comp.scan_a.overall_app_score;
    const verdictText = comp.scan_a.overall_app_score === comp.scan_b.overall_app_score
      ? "Both applications carry equal risk severity."
      : isBMoreRisky
      ? `<strong>${comp.scan_b.app_name}</strong> is <strong>${Math.abs(diff)} points higher risk</strong> than ${comp.scan_a.app_name}!`
      : `<strong>${comp.scan_a.app_name}</strong> is <strong>${Math.abs(diff)} points higher risk</strong> than ${comp.scan_b.app_name}!`;

    let html = `
      <div class="compare-verdict-card">
        <h4 style="font-size: 16px; margin-bottom: 6px;"><i class="fa-solid fa-scale-unbalanced-flip text-accent"></i> Comparison Verdict</h4>
        <p style="font-size: 14px; color: var(--text-primary);">${verdictText}</p>
      </div>

      <div class="compare-metrics-grid">
        <div class="compare-col-card">
          <h5 style="font-weight: 800; font-size: 15px; margin-bottom: 8px;">Baseline: ${comp.scan_a.app_name}</h5>
          <div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-secondary); line-height: 1.8;">
            • Overall Score: <strong>${comp.scan_a.overall_app_score} / 100 (${comp.scan_a.overall_tier})</strong><br>
            • Critical Vulns: ${comp.scan_a.critical_count}<br>
            • High Vulns: ${comp.scan_a.high_count}<br>
            • Total Vulns: ${comp.scan_a.total_vulnerabilities}
          </div>
        </div>

        <div class="compare-col-card">
          <h5 style="font-weight: 800; font-size: 15px; margin-bottom: 8px;">Target: ${comp.scan_b.app_name}</h5>
          <div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-secondary); line-height: 1.8;">
            • Overall Score: <strong>${comp.scan_b.overall_app_score} / 100 (${comp.scan_b.overall_tier})</strong> 
              <span class="delta-tag ${diff > 0 ? 'delta-danger' : diff < 0 ? 'delta-success' : ''}">${diff >= 0 ? '+' : ''}${diff}</span><br>
            • Critical Vulns: ${comp.scan_b.critical_count}<br>
            • High Vulns: ${comp.scan_b.high_count}<br>
            • Total Vulns: ${comp.scan_b.total_vulnerabilities}
          </div>
        </div>
      </div>
    `;

    if (comp.new_vulnerabilities && comp.new_vulnerabilities.length > 0) {
      html += `
        <div style="margin-top: 14px;">
          <h5 style="font-size: 14px; font-weight: 700; color: var(--sev-critical); margin-bottom: 6px;">🆕 New Vulnerabilities in Target App (${comp.new_vulnerabilities.length}):</h5>
          <div class="cli-code" style="display:block; padding: 10px; font-size: 12px; color: #fca5a5;">
            ${comp.new_vulnerabilities.slice(0, 5).map(v => `• ${v.cve_id} (${v.component})`).join("<br>")}
            ${comp.new_vulnerabilities.length > 5 ? `<br>+ ${comp.new_vulnerabilities.length - 5} more...` : ""}
          </div>
        </div>
      `;
    }

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div style="color: var(--sev-critical); text-align:center;">Failed to compute comparison: ${err.message}</div>`;
  }
}

// Enterprise Feature 5: SARIF Export
function exportSARIF() {
  if (!appState.analysisResults) return;
  const scanId = appState.analysisResults.scan_id || 1;
  window.open(`/api/export/sarif/${scanId}`, "_blank");
}

function showRemediationModal(index) {
  const item = appState.analysisResults.remediations[index];
  const modalBody = document.getElementById("modalBody");
  const annKey = `${item.cve_id}_${item.component}`;
  const ann = appState.annotations[annKey] || { status: "OPEN" };

  modalBody.innerHTML = `
    <div style="margin-bottom: 16px;">
      <h4 style="font-size: 18px; margin-bottom: 4px;">${item.cve_id} - ${item.component}</h4>
      <p style="font-size: 13px; color: var(--text-muted);">${item.description}</p>
    </div>
    
    <div class="card" style="background: rgba(255,255,255,0.02); margin-bottom: 16px;">
      <div style="font-size: 13px; font-weight: 700; margin-bottom: 8px;">📊 Risk Factor Scoring Breakdown</div>
      <div style="font-size: 12px; font-family: var(--font-mono); color: #a5f3fc; line-height: 1.8;">
        • CVSS Score (${item.cvss_score}/10): +${item.factor_breakdown.cvss_contrib} pts<br>
        • Internet Exposure (${appState.internetExposure}): +${item.factor_breakdown.exposure_contrib} pts<br>
        • Business Criticality (${appState.businessCriticality}): +${item.factor_breakdown.criticality_contrib} pts<br>
        • Exploit Availability (${item.exploit_available ? 'Yes' : 'No'}): +${item.factor_breakdown.exploit_contrib} pts<br>
        • Dependency Importance (${item.is_direct_dependency ? 'Direct' : 'Transitive'}): +${item.factor_breakdown.dep_contrib} pts<br>
        <strong>TOTAL RISK SCORE: ${item.risk_score} / 100 (${item.risk_tier})</strong>
      </div>
    </div>

    <div style="margin-bottom: 16px;">
      <div style="font-size: 13px; font-weight: 700; margin-bottom: 6px;">🏷️ Triage Status & Annotation:</div>
      <select class="form-control" style="font-weight:700;" onchange="saveVulnerabilityAnnotation('${item.cve_id}', '${item.component}', this.value)">
        <option value="OPEN" ${ann.status === "OPEN" ? "selected" : ""}>🔴 OPEN - Action Required</option>
        <option value="ACCEPTED RISK" ${ann.status === "ACCEPTED RISK" ? "selected" : ""}>🟡 ACCEPTED RISK - Business Exemption</option>
        <option value="FALSE POSITIVE" ${ann.status === "FALSE POSITIVE" ? "selected" : ""}>⚪ FALSE POSITIVE - Not Applicable</option>
        <option value="IN PROGRESS" ${ann.status === "IN PROGRESS" ? "selected" : ""}>🔵 IN PROGRESS - Remediation Active</option>
        <option value="RESOLVED" ${ann.status === "RESOLVED" ? "selected" : ""}>🟢 RESOLVED - Patch Verified</option>
      </select>
    </div>

    <div style="margin-bottom: 16px;">
      <div style="font-size: 13px; font-weight: 700; margin-bottom: 6px;">🔧 Fix Command:</div>
      <div class="cli-code" style="display: block; padding: 12px;">${item.remediation.cli_command}</div>
    </div>
    
    <div>
      <div style="font-size: 13px; font-weight: 700; margin-bottom: 4px;">⏰ Urgency Timeline:</div>
      <span class="badge badge-danger">${item.remediation.urgency}</span>
    </div>
  `;

  document.getElementById("modalRemediation").classList.remove("hidden");
}

function closeModal() {
  document.getElementById("modalRemediation").classList.add("hidden");
}

function exportCSV() {
  if (!appState.analysisResults) return;

  const items = appState.analysisResults.remediations;
  let csv = "Rank,Risk Score,Risk Tier,CVE ID,Component,Current Version,Fixed Version,CVSS,Exploit Available,Fix Action\n";

  items.forEach((item, index) => {
    csv += `"${index + 1}","${item.risk_score}","${item.risk_tier}","${item.cve_id}","${item.component}","${item.current_version}","${item.fixed_version}","${item.cvss_score}","${item.exploit_available}","${item.remediation.primary_action}"\n`;
  });

  const blob = new Blob([csv], { type: "text/csv" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.setAttribute("href", url);
  a.setAttribute("download", `cyber_risk_report_${appState.appName.replace(/\s+/g, "_")}.csv`);
  a.click();
}

function exportJSON() {
  if (!appState.analysisResults) return;
  const jsonStr = JSON.stringify(appState.analysisResults, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.setAttribute("href", url);
  a.setAttribute("download", `cyber_risk_report_${appState.appName.replace(/\s+/g, "_")}.json`);
  a.click();
}
