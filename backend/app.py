"""
Cyber Risk Prioritization Platform — Backend API Server
Endpoints:
  GET  /api/health                    — Health check
  GET  /api/sample-data               — Standard 6-vuln demo dataset
  GET  /api/sample-large-data         — 500-vuln enterprise dataset
  POST /api/analyze                   — Full analysis pipeline (+ NVD/EPSS enrichment)
  POST /api/scan                      — CI/CD-friendly alias for /api/analyze (returns SARIF by default)
  GET  /api/history                   — Retrieve scan history (optional ?app=AppName)
  GET  /api/history/<id>              — Get full scan result by ID
  GET  /api/history/apps              — Get all unique app names from history
  POST /api/compare                   — Compare two scans (?scan_a=1&scan_b=2)
  GET  /api/export/sarif/<scan_id>    — Export scan as SARIF 2.1.0 JSON
  GET  /api/export/report/<scan_id>   — Export scan as professional HTML report (print-to-PDF)
  POST /api/annotations               — Create/update annotation for a vuln
  GET  /api/annotations/<scan_id>     — Get all annotations for a scan
  DELETE /api/annotations/<ann_id>    — Delete an annotation
  POST /api/sbom/parse                — Auto-parse any SBOM format or dep file
  GET  /api/nvd/<cve_id>             — Fetch live NVD CVE details
  POST /api/cache/clear               — Clear NVD/EPSS cache
"""
import json
import os
import sys
import webbrowser
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sbom_parser import SBOMParser
from vuln_parser import UniversalVulnParser
from vuln_matcher import VulnerabilityMatcher
from risk_engine import RiskScoringEngine
from remediator import RemediationRecommender
from nvd_fetcher import fetch_cve_details, fetch_epss_scores, enrich_vulnerabilities_with_live_data, clear_cache
from scan_history import (
    save_scan, get_scan_history, get_scan_by_id, compare_scans,
    get_all_app_names, upsert_annotation, get_annotations, delete_annotation,
    get_all_sboms, get_sbom_by_id, save_sbom, delete_sbom
)
from sarif_exporter import export_sarif
from report_generator import generate_html_report

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")

# NVD enrichment is opt-in (add ?enrich=true to /api/analyze)
# to avoid slowing down demo runs
NVD_ENRICH_DEFAULT = False


# ─────────────────────────────────────────────────────────────────────────────
# Analysis pipeline helper
# ─────────────────────────────────────────────────────────────────────────────

def _run_analysis_pipeline(data: dict, enrich: bool = False) -> dict:
    """
    Core 6-step analysis pipeline used by both /api/analyze and /api/scan.
    """
    app_details = {
        "app_name":             data.get("app_name", "Default Application"),
        "business_criticality": data.get("business_criticality", "High"),
        "internet_exposure":    data.get("internet_exposure", "High"),
        "app_type":             data.get("app_type", "Web Application")
    }

    sbom_input = data.get("sbom_content")
    sbom_id = data.get("sbom_id")

    if not sbom_input and sbom_id:
        sbom_record = get_sbom_by_id(int(sbom_id))
        if sbom_record:
            sbom_input = sbom_record.get("content")
            if not data.get("app_name") or data.get("app_name") == "Default Application":
                app_details["app_name"] = sbom_record.get("name")

    vuln_input = data.get("vuln_content")

    if not sbom_input and not vuln_input:
        raise ValueError("Please provide at least an SBOM file or a Vulnerability report file.")

    # Step 1: Parse SBOM (if provided)
    components = []
    if sbom_input:
        components = SBOMParser.parse_sbom_data(sbom_input)

    # Steps 2 & 3: Component Identification & Vulnerability Matching
    matched_vulns = VulnerabilityMatcher.match_vulnerabilities(components, vuln_input)

    # If user provided vulnerability findings but no SBOM, auto-derive components from the findings!
    if not components and matched_vulns:
        seen_comps = set()
        for v in matched_vulns:
            c_name = v.get("component", "app-component")
            if c_name not in seen_comps:
                seen_comps.add(c_name)
                components.append({
                    "name": c_name,
                    "version": v.get("current_version", "unknown"),
                    "purl": f"pkg:generic/{c_name}@{v.get('current_version', '0.0')}",
                    "type": "library",
                    "is_direct": v.get("is_direct_dependency", True)
                })

    # Step 3b (optional): NVD & EPSS enrichment
    if enrich and matched_vulns:
        matched_vulns = enrich_vulnerabilities_with_live_data(matched_vulns)

    # Steps 4 & 5: Risk Scoring & Prioritization
    risk_summary = RiskScoringEngine.calculate_risk_scores(matched_vulns, app_details)

    # Step 6: Remediation Recommender
    final_recommendations = RemediationRecommender.generate_recommendations(
        risk_summary["prioritized_list"]
    )

    return {
        "status": "success",
        "application": app_details,
        "total_components": len(components),
        "risk_summary": {
            "overall_app_score":   risk_summary["overall_app_score"],
            "overall_tier":        risk_summary["overall_tier"],
            "total_vulnerabilities": risk_summary["total_vulnerabilities"],
            "critical_count":      risk_summary["critical_count"],
            "high_count":          risk_summary["high_count"],
            "medium_count":        risk_summary["medium_count"],
            "low_count":           risk_summary["low_count"],
            "alerts":              risk_summary.get("alerts", []),
            "epss_enabled":        risk_summary.get("epss_enabled", False),
        },
        "components": components,
        "remediations": final_recommendations
    }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Server
# ─────────────────────────────────────────────────────────────────────────────

class CyberRiskServer(BaseHTTPRequestHandler):
    """
    Main Backend HTTP Server for Cyber Risk Prioritization Platform.
    Provides comprehensive API endpoints and serves frontend static assets.
    """

    def log_message(self, fmt, *args):
        # Suppress verbose default access logs; print only errors
        pass

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def _serve_static_file(self, req_path: str):
        if req_path in ("/", "/index.html"):
            filename = "index.html"
        else:
            filename = req_path.lstrip("/")

        filepath = os.path.join(FRONTEND_DIR, filename)

        if not os.path.isfile(filepath):
            self.send_json({"error": f"File {filename} not found"}, 404)
            return

        content_type = "text/html"
        if filepath.endswith(".css"):
            content_type = "text/css"
        elif filepath.endswith(".js"):
            content_type = "application/javascript"
        elif filepath.endswith(".json"):
            content_type = "application/json"
        elif filepath.endswith(".png"):
            content_type = "image/png"
        elif filepath.endswith(".ico"):
            content_type = "image/x-icon"

        try:
            with open(filepath, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    # ── GET routing ──────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        params = parse_qs(parsed.query)

        if path == "/api/health":
            self.send_json({"status": "healthy", "service": "Cyber Risk Engine", "version": "2.0.0"})

        elif path == "/api/sample-data":
            self._handle_sample_data(large=False)

        elif path == "/api/sample-large-data":
            self._handle_sample_data(large=True)

        elif path == "/api/history":
            app_name = params.get("app", [None])[0]
            limit    = int(params.get("limit", ["20"])[0])
            self.send_json(get_scan_history(app_name, limit))

        elif path == "/api/history/apps":
            self.send_json({"apps": get_all_app_names()})

        elif path.startswith("/api/history/"):
            scan_id = self._extract_id(path, "/api/history/")
            result  = get_scan_by_id(scan_id)
            if result:
                self.send_json(result)
            else:
                self.send_json({"error": f"Scan ID {scan_id} not found."}, 404)

        elif path.startswith("/api/export/sarif/"):
            scan_id = self._extract_id(path, "/api/export/sarif/")
            result  = get_scan_by_id(scan_id)
            if not result:
                self.send_json({"error": f"Scan ID {scan_id} not found."}, 404)
                return
            sarif = export_sarif(result)
            self.send_response(200)
            self.send_header("Content-Type", "application/sarif+json")
            self.send_header("Content-Disposition",
                             f'attachment; filename="scan_{scan_id}.sarif.json"')
            self._cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(sarif, indent=2).encode("utf-8"))

        elif path.startswith("/api/export/report/"):
            scan_id = self._extract_id(path, "/api/export/report/")
            result  = get_scan_by_id(scan_id)
            if not result:
                self.send_json({"error": f"Scan ID {scan_id} not found."}, 404)
                return
            html = generate_html_report(result, scan_id=scan_id)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        elif path.startswith("/api/annotations/"):
            scan_id = self._extract_id(path, "/api/annotations/")
            self.send_json(get_annotations(scan_id))

        elif path.rstrip("/") == "/api/sboms":
            self.send_json(get_all_sboms())

        elif path.startswith("/api/sboms/"):
            sbom_id = self._extract_id(path, "/api/sboms/")
            res = get_sbom_by_id(sbom_id)
            if res:
                self.send_json(res)
            else:
                self.send_json({"error": f"SBOM ID {sbom_id} not found."}, 404)

        elif path.startswith("/api/nvd/"):
            cve_id  = path.replace("/api/nvd/", "").strip()
            details = fetch_cve_details(cve_id)
            self.send_json(details or {"error": f"Could not fetch NVD data for {cve_id}"})

        else:
            self._serve_static_file(path)

    # ── POST routing ─────────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        params = parse_qs(parsed.query)
        body   = self._read_body()

        if path in ("/api/analyze", "/api/scan"):
            self._handle_analyze(body, params, path == "/api/scan")

        elif path == "/api/sboms":
            name = body.get("name")
            desc = body.get("description", "")
            app_type = body.get("app_type", "Web Application")
            content = body.get("content")
            if not name or not content:
                self.send_json({"error": "Both 'name' and 'content' are required to save an SBOM."}, 400)
                return
            new_id = save_sbom(name, desc, content, app_type)
            self.send_json({"status": "success", "id": new_id, "name": name})

        elif path == "/api/compare":
            self._handle_compare(body, params)

        elif path == "/api/annotations":
            self._handle_upsert_annotation(body)

        elif path == "/api/sbom/parse":
            self._handle_sbom_parse(body)

        elif path == "/api/vuln/parse":
            self._handle_vuln_parse(body)

        elif path == "/api/cache/clear":
            clear_cache()
            self.send_json({"status": "ok", "message": "NVD/EPSS cache cleared."})

        else:
            self.send_json({"error": "Endpoint not found."}, 404)

    # ── DELETE routing ────────────────────────────────────────────────────────

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        if path.startswith("/api/annotations/"):
            ann_id = self._extract_id(path, "/api/annotations/")
            deleted = delete_annotation(ann_id)
            self.send_json({"deleted": deleted, "id": ann_id})
        elif path.startswith("/api/sboms/"):
            sbom_id = self._extract_id(path, "/api/sboms/")
            deleted = delete_sbom(sbom_id)
            self.send_json({"deleted": deleted, "id": sbom_id})
        else:
            self.send_json({"error": "Endpoint not found."}, 404)

    # ── Handler implementations ──────────────────────────────────────────────

    def _handle_sample_data(self, large: bool):
        try:
            sbom_file = "real_sbom_large.json" if large else "real_sbom.json"
            vuln_file = "real_vulnerabilities_500.json" if large else "real_vulnerabilities.json"
            with open(os.path.join(DATA_DIR, sbom_file), "r", encoding="utf-8") as f:
                sample_sbom = json.load(f)
            with open(os.path.join(DATA_DIR, vuln_file), "r", encoding="utf-8") as f:
                sample_vulns = json.load(f)
            self.send_json({
                "app_name":             "Enterprise Banking & FinTech Core API" if large else "Production E-Commerce Core API",
                "business_criticality": "High",
                "internet_exposure":    "High",
                "app_type":             "Web Application / API Service",
                "sbom_content":         sample_sbom,
                "vuln_content":         sample_vulns
            })
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def _handle_analyze(self, body: dict, params: dict, is_ci_cd: bool):
        try:
            enrich = params.get("enrich", ["false"])[0].lower() in ("true", "1", "yes")
            result = _run_analysis_pipeline(body, enrich=enrich)

            # Save to scan history
            scan_id = save_scan(result["application"]["app_name"], result)
            result["scan_id"] = scan_id

            # CI/CD mode: also return SARIF inline
            if is_ci_cd:
                result["sarif"] = export_sarif(result)

            self.send_json(result)
        except ValueError as e:
            self.send_json({"error": str(e)}, 400)
        except Exception as e:
            self.send_json({"error": f"Processing failed: {str(e)}"}, 500)

    def _handle_compare(self, body: dict, params: dict):
        try:
            scan_a = int(params.get("scan_a", [body.get("scan_a", 0)])[0])
            scan_b = int(params.get("scan_b", [body.get("scan_b", 0)])[0])
            if not scan_a or not scan_b:
                self.send_json({"error": "Provide scan_a and scan_b query params or body fields."}, 400)
                return
            self.send_json(compare_scans(scan_a, scan_b))
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def _handle_upsert_annotation(self, body: dict):
        try:
            result = upsert_annotation(
                scan_id   = int(body.get("scan_id", 0)),
                cve_id    = body.get("cve_id", ""),
                component = body.get("component", ""),
                status    = body.get("status", "OPEN"),
                assignee  = body.get("assignee", ""),
                note      = body.get("note", "")
            )
            self.send_json(result)
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def _handle_sbom_parse(self, body: dict):
        try:
            filename = body.get("filename", "sbom.json")
            content  = body.get("content", "")
            components = SBOMParser.auto_detect_and_parse(filename, content)
            self.send_json({
                "filename": filename,
                "components": components,
                "count": len(components)
            })
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def _handle_vuln_parse(self, body: dict):
        try:
            filename = body.get("filename", "vulnerabilities.json")
            content  = body.get("content", "")
            vulns, fmt = UniversalVulnParser.parse(content, filename)
            self.send_json({
                "filename": filename,
                "vulnerabilities": vulns,
                "count": len(vulns),
                "detected_format": fmt
            })
        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _extract_id(self, path: str, prefix: str) -> int:
        try:
            return int(path.replace(prefix, "").strip("/"))
        except ValueError:
            return 0

    def send_json(self, data: dict, status: int = 200):
        payload = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(payload)


# ─────────────────────────────────────────────────────────────────────────────

def run(port: int = 8000):
    actual_port = port
    httpd = None
    for try_port in [port, 8001, 8080, 8500, 9000]:
        try:
            server_address = ("127.0.0.1", try_port)
            ThreadingHTTPServer.allow_reuse_address = True
            httpd = ThreadingHTTPServer(server_address, CyberRiskServer)
            actual_port = try_port
            break
        except OSError:
            continue

    if not httpd:
        print(f"[ERROR] Could not bind to port {port} or fallback ports.")
        return

    url = f"http://127.0.0.1:{actual_port}"
    print(f"\n=======================================================", flush=True)
    print(f" [OK] Cyber Risk Platform v2.0 is running!", flush=True)
    print(f" [URL] Open in Chrome: {url}", flush=True)
    print(f"=======================================================\n", flush=True)

    def _open_browser():
        time.sleep(1.0)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_open_browser, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[STOP] Server stopped successfully.")


if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run(port)
