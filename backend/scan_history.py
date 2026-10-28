"""
Module: Scan History Manager
Stores, retrieves, and compares historical scan results using SQLite.
Enables scan versioning, trend analysis, and multi-app comparison.
"""
import json
import os
import sqlite3
import time
from typing import Dict, List, Optional, Any

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".scan_history.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize SQLite schema on first run."""
    conn = _get_conn()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name    TEXT NOT NULL,
                scan_time   INTEGER NOT NULL,
                overall_score REAL,
                overall_tier  TEXT,
                total_vulns   INTEGER,
                critical_count INTEGER,
                high_count     INTEGER,
                medium_count   INTEGER,
                low_count      INTEGER,
                full_payload   TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_app_name ON scans(app_name)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS annotations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER,
                cve_id      TEXT NOT NULL,
                component   TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'OPEN',
                assignee    TEXT,
                note        TEXT,
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sboms (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL UNIQUE,
                description     TEXT,
                app_type        TEXT DEFAULT 'Web Application',
                component_count INTEGER DEFAULT 0,
                content         TEXT NOT NULL,
                created_at      INTEGER NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()

    seed_default_sboms()


def seed_default_sboms():
    """Seed fixed default SBOMs into SQLite database if none exist."""
    conn = _get_conn()
    try:
        count = conn.execute("SELECT COUNT(*) FROM sboms").fetchone()[0]
        if count > 0:
            return

        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

        # 1. Standard SBOM
        path_std = os.path.join(data_dir, "real_sbom.json")
        if os.path.exists(path_std):
            with open(path_std, "r", encoding="utf-8") as f:
                content_std = json.load(f)
            comps_std = content_std.get("components", [])
            conn.execute("""
                INSERT INTO sboms (name, description, app_type, component_count, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "Production E-Commerce API (Fixed DB)",
                "Standard 6-component Python/Java E-Commerce Stack",
                "Web Application",
                len(comps_std),
                json.dumps(content_std),
                int(time.time())
            ))

        # 2. Large Enterprise SBOM
        path_large = os.path.join(data_dir, "real_sbom_large.json")
        if os.path.exists(path_large):
            with open(path_large, "r", encoding="utf-8") as f:
                content_large = json.load(f)
            comps_large = content_large.get("components", [])
            conn.execute("""
                INSERT INTO sboms (name, description, app_type, component_count, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "Enterprise Cloud Native Stack (Fixed DB - 500+ Vuln Ready)",
                "Enterprise-scale Microservice Cluster Stack with 100+ components",
                "Microservice",
                len(comps_large),
                json.dumps(content_large),
                int(time.time())
            ))

        conn.commit()
    except Exception as e:
        print(f"[WARN] Failed to seed default SBOMs: {e}")
    finally:
        conn.close()


def save_sbom(name: str, description: str, content: Dict, app_type: str = "Web Application") -> int:
    """Save an SBOM to database permanently."""
    init_db()
    conn = _get_conn()
    now = int(time.time())
    comps = content.get("components", content.get("packages", []))
    try:
        cur = conn.execute("""
            INSERT OR REPLACE INTO sboms (name, description, app_type, component_count, content, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, description, app_type, len(comps), json.dumps(content), now))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_all_sboms() -> List[Dict]:
    """Retrieve all fixed/saved SBOMs in database."""
    init_db()
    conn = _get_conn()
    try:
        rows = conn.execute("""
            SELECT id, name, description, app_type, component_count, created_at
            FROM sboms ORDER BY id ASC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_sbom_by_id(sbom_id: int) -> Optional[Dict]:
    """Retrieve a full saved SBOM by ID."""
    init_db()
    conn = _get_conn()
    try:
        row = conn.execute("SELECT * FROM sboms WHERE id=?", (sbom_id,)).fetchone()
        if row:
            res = dict(row)
            res["content"] = json.loads(res["content"])
            return res
        return None
    finally:
        conn.close()


def delete_sbom(sbom_id: int) -> bool:
    """Delete a saved SBOM from database."""
    init_db()
    conn = _get_conn()
    try:
        cur = conn.execute("DELETE FROM sboms WHERE id=?", (sbom_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def save_scan(app_name: str, analysis_result: Dict) -> int:
    """
    Persist a completed analysis result.
    Returns the scan ID.
    """
    init_db()
    summary = analysis_result.get("risk_summary", {})
    conn = _get_conn()
    try:
        cur = conn.execute("""
            INSERT INTO scans
            (app_name, scan_time, overall_score, overall_tier, total_vulns,
             critical_count, high_count, medium_count, low_count, full_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            app_name,
            int(time.time()),
            summary.get("overall_app_score", 0.0),
            summary.get("overall_tier", "UNKNOWN"),
            summary.get("total_vulnerabilities", 0),
            summary.get("critical_count", 0),
            summary.get("high_count", 0),
            summary.get("medium_count", 0),
            summary.get("low_count", 0),
            json.dumps(analysis_result)
        ))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_scan_history(app_name: Optional[str] = None, limit: int = 20) -> List[Dict]:
    """
    Retrieve past scan summaries, optionally filtered by app_name.
    Returns lightweight records (no full payload).
    """
    init_db()
    conn = _get_conn()
    try:
        if app_name:
            rows = conn.execute("""
                SELECT id, app_name, scan_time, overall_score, overall_tier,
                       total_vulns, critical_count, high_count, medium_count, low_count
                FROM scans WHERE app_name = ?
                ORDER BY scan_time DESC LIMIT ?
            """, (app_name, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, app_name, scan_time, overall_score, overall_tier,
                       total_vulns, critical_count, high_count, medium_count, low_count
                FROM scans ORDER BY scan_time DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_by_id(scan_id: int) -> Optional[Dict]:
    """Retrieve a full scan result by its ID."""
    init_db()
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT full_payload FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row:
            return json.loads(row["full_payload"])
        return None
    finally:
        conn.close()


def compare_scans(scan_id_a: int, scan_id_b: int) -> Dict:
    """
    Compare two scan results and return a diff highlighting new/resolved/persistent vulns.
    """
    init_db()
    conn = _get_conn()
    try:
        def _get_summary(scan_id):
            row = conn.execute(
                "SELECT app_name, scan_time, overall_score, overall_tier, total_vulns, "
                "critical_count, high_count, medium_count, low_count, full_payload FROM scans WHERE id = ?",
                (scan_id,)
            ).fetchone()
            return dict(row) if row else None

        scan_a = _get_summary(scan_id_a)
        scan_b = _get_summary(scan_id_b)
        if not scan_a or not scan_b:
            return {"error": "One or both scan IDs not found."}

        payload_a = json.loads(scan_a.pop("full_payload"))
        payload_b = json.loads(scan_b.pop("full_payload"))

        cves_a = {r["cve_id"] for r in payload_a.get("remediations", [])}
        cves_b = {r["cve_id"] for r in payload_b.get("remediations", [])}

        new_in_b = cves_b - cves_a
        resolved_in_b = cves_a - cves_b
        persistent = cves_a & cves_b

        return {
            "scan_a": {**scan_a, "scan_id": scan_id_a},
            "scan_b": {**scan_b, "scan_id": scan_id_b},
            "diff": {
                "new_vulnerabilities": list(new_in_b),
                "resolved_vulnerabilities": list(resolved_in_b),
                "persistent_vulnerabilities": list(persistent),
                "score_change": round(scan_b["overall_score"] - scan_a["overall_score"], 1),
                "vuln_count_change": scan_b["total_vulns"] - scan_a["total_vulns"]
            }
        }
    finally:
        conn.close()


def get_all_app_names() -> List[str]:
    """Return a distinct list of application names from scan history."""
    init_db()
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT DISTINCT app_name FROM scans ORDER BY app_name"
        ).fetchall()
        return [r["app_name"] for r in rows]
    finally:
        conn.close()


# ── Annotation CRUD ────────────────────────────────────────────

def upsert_annotation(scan_id: int, cve_id: str, component: str,
                       status: str, assignee: str = "", note: str = "") -> Dict:
    """
    Create or update a vulnerability annotation (Accept Risk / False Positive / Assigned).
    """
    init_db()
    now = int(time.time())
    conn = _get_conn()
    try:
        existing = conn.execute(
            "SELECT id FROM annotations WHERE scan_id=? AND cve_id=? AND component=?",
            (scan_id, cve_id, component)
        ).fetchone()

        if existing:
            conn.execute("""
                UPDATE annotations SET status=?, assignee=?, note=?, updated_at=?
                WHERE id=?
            """, (status, assignee, note, now, existing["id"]))
            annotation_id = existing["id"]
        else:
            cur = conn.execute("""
                INSERT INTO annotations (scan_id, cve_id, component, status, assignee, note, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, cve_id, component, status, assignee, note, now, now))
            annotation_id = cur.lastrowid

        conn.commit()
        return {"id": annotation_id, "scan_id": scan_id, "cve_id": cve_id,
                "component": component, "status": status, "assignee": assignee,
                "note": note, "updated_at": now}
    finally:
        conn.close()


def get_annotations(scan_id: int) -> List[Dict]:
    """Retrieve all annotations for a given scan."""
    init_db()
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM annotations WHERE scan_id=? ORDER BY updated_at DESC", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_annotation(annotation_id: int) -> bool:
    """Delete an annotation by ID."""
    init_db()
    conn = _get_conn()
    try:
        cur = conn.execute("DELETE FROM annotations WHERE id=?", (annotation_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()
