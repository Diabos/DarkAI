"""
DarkAI — REST API & Web Dashboard Server
==========================================
Flask application serving:
  • Web dashboard (GET /)
  • REST API endpoints (/api/...)
  • Export functionality (JSON / CSV)

Runs in a background thread alongside the crawler.
"""

import os
import io
import csv
import json
import sqlite3
import hashlib
import logging
from datetime import datetime
from functools import wraps
from collections import defaultdict
from flask import Flask, jsonify, request, render_template, send_file, abort, Response

log = logging.getLogger("sentinel.api")

DB_PATH   = os.path.join(os.getenv("DATA_DIR", "/app/data"), "crawler.db")
API_PORT  = int(os.getenv("API_PORT", "5000"))
API_HOST  = os.getenv("API_HOST", "0.0.0.0")
DATA_DIR  = os.getenv("DATA_DIR", "/app/data")

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)
app.config["JSON_SORT_KEYS"] = False

# ──────────────────────────────────────────────
#  Shared state (set by main.py before starting)
# ──────────────────────────────────────────────
crawler_state = {
    "status": "initializing",
    "scan_count": 0,
    "start_time": None,
    "consec_fail": 0,
    "current_url": None,
}


def get_db():
    """Thread-safe read-only DB connection."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA query_only=ON")
    return conn


def db_read(func):
    """Decorator: auto-open and auto-close a read connection."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            conn = get_db()
            result = func(conn, *args, **kwargs)
            conn.close()
            return result
        except sqlite3.OperationalError as e:
            return jsonify({"error": f"Database error: {e}"}), 500
    return wrapper


# ──────────────────────────────────────────────
#  Dashboard
# ──────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("index.html")


# ──────────────────────────────────────────────
#  API: Status
# ──────────────────────────────────────────────

@app.route("/api/status")
@db_read
def api_status(conn):
    c = conn.cursor()
    total   = c.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    threats = c.execute("SELECT COUNT(*) FROM sites WHERE is_threat=1").fetchone()[0]
    pending = c.execute("SELECT COUNT(*) FROM queue WHERE status='pending'").fetchone()[0]
    visited = c.execute("SELECT COUNT(*) FROM queue WHERE status='visited'").fetchone()[0]
    failed  = c.execute("SELECT COUNT(*) FROM queue WHERE status='failed'").fetchone()[0]

    leaks = 0
    try:
        leaks = c.execute("SELECT COUNT(*) FROM leaks").fetchone()[0]
    except sqlite3.OperationalError:
        pass

    kw_hits = 0
    try:
        kw_hits = c.execute("SELECT COUNT(*) FROM keyword_hits").fetchone()[0]
    except sqlite3.OperationalError:
        pass

    uptime = None
    if crawler_state["start_time"]:
        uptime = str(datetime.utcnow() - crawler_state["start_time"]).split(".")[0]

    return jsonify({
        "crawler": crawler_state["status"],
        "current_url": crawler_state["current_url"],
        "scan_count": crawler_state["scan_count"],
        "uptime": uptime,
        "consec_failures": crawler_state["consec_fail"],
        "stats": {
            "total_sites": total,
            "threats": threats,
            "safe": total - threats,
            "leaks_found": leaks,
            "keyword_hits": kw_hits,
            "queue_pending": pending,
            "queue_visited": visited,
            "queue_failed": failed,
        },
    })


# ──────────────────────────────────────────────
#  API: Sites
# ──────────────────────────────────────────────

@app.route("/api/sites")
@db_read
def api_sites(conn):
    c = conn.cursor()
    threat_only = request.args.get("threats", "").lower() == "true"
    category    = request.args.get("category", "")
    limit       = min(int(request.args.get("limit", "500")), 5000)
    offset      = int(request.args.get("offset", "0"))

    query = "SELECT url, category, score, is_threat, scanned_at FROM sites"
    params = []
    conditions = []

    if threat_only:
        conditions.append("is_threat=1")
    if category:
        conditions.append("category=?")
        params.append(category)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY scanned_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = c.execute(query, params).fetchall()
    return jsonify({
        "count": len(rows),
        "sites": [dict(r) for r in rows],
    })


@app.route("/api/sites/<path:url>")
@db_read
def api_site_detail(conn, url):
    c = conn.cursor()
    site = c.execute(
        "SELECT url, category, score, is_threat, scanned_at FROM sites WHERE url=?", (url,)
    ).fetchone()
    if not site:
        return jsonify({"error": "Site not found"}), 404

    result = dict(site)

    # Get leaks for this site
    try:
        leaks = c.execute("SELECT leak_type, leak_value, found_at FROM leaks WHERE url=?", (url,)).fetchall()
        result["leaks"] = [dict(l) for l in leaks]
    except sqlite3.OperationalError:
        result["leaks"] = []

    # Get keyword hits
    try:
        kw = c.execute("SELECT keyword, context, found_at FROM keyword_hits WHERE url=?", (url,)).fetchall()
        result["keyword_hits"] = [dict(k) for k in kw]
    except sqlite3.OperationalError:
        result["keyword_hits"] = []

    # Get outgoing links
    try:
        links_out = c.execute("SELECT target_url FROM link_graph WHERE source_url=?", (url,)).fetchall()
        result["links_out"] = [r[0] for r in links_out]
    except sqlite3.OperationalError:
        result["links_out"] = []

    # Get incoming links
    try:
        links_in = c.execute("SELECT source_url FROM link_graph WHERE target_url=?", (url,)).fetchall()
        result["links_in"] = [r[0] for r in links_in]
    except sqlite3.OperationalError:
        result["links_in"] = []

    # Get page content
    try:
        content = c.execute("SELECT text_content, html_hash FROM page_content WHERE url=?", (url,)).fetchone()
        if content:
            result["content_preview"] = content["text_content"][:2000] if content["text_content"] else ""
            result["content_hash"] = content["html_hash"]
    except sqlite3.OperationalError:
        pass

    return jsonify(result)


# ──────────────────────────────────────────────
#  API: Threats
# ──────────────────────────────────────────────

@app.route("/api/threats")
@db_read
def api_threats(conn):
    rows = conn.execute(
        "SELECT url, category, score, scanned_at FROM sites WHERE is_threat=1 ORDER BY score DESC"
    ).fetchall()
    return jsonify({"count": len(rows), "threats": [dict(r) for r in rows]})


# ──────────────────────────────────────────────
#  API: Leaks
# ──────────────────────────────────────────────

@app.route("/api/leaks")
@db_read
def api_leaks(conn):
    try:
        leak_type = request.args.get("type", "")
        query = "SELECT id, url, leak_type, leak_value, found_at FROM leaks"
        params = []
        if leak_type:
            query += " WHERE leak_type=?"
            params.append(leak_type)
        query += " ORDER BY found_at DESC LIMIT 1000"
        rows = conn.execute(query, params).fetchall()

        # Summary by type
        summary = conn.execute(
            "SELECT leak_type, COUNT(*) as count FROM leaks GROUP BY leak_type ORDER BY count DESC"
        ).fetchall()

        return jsonify({
            "count": len(rows),
            "leaks": [dict(r) for r in rows],
            "summary": {r["leak_type"]: r["count"] for r in summary},
        })
    except sqlite3.OperationalError:
        return jsonify({"count": 0, "leaks": [], "summary": {}})


# ──────────────────────────────────────────────
#  API: Keywords
# ──────────────────────────────────────────────

@app.route("/api/keywords", methods=["GET"])
@db_read
def api_keywords_get(conn):
    try:
        rows = conn.execute("SELECT id, keyword, added_at FROM keywords ORDER BY added_at DESC").fetchall()
        return jsonify({"keywords": [dict(r) for r in rows]})
    except sqlite3.OperationalError:
        return jsonify({"keywords": []})


@app.route("/api/keywords", methods=["POST"])
def api_keywords_add():
    data = request.get_json(silent=True) or {}
    keyword = (data.get("keyword") or "").strip()
    if not keyword:
        return jsonify({"error": "keyword is required"}), 400
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute(
            "INSERT OR IGNORE INTO keywords (keyword, added_at) VALUES (?, datetime('now'))",
            (keyword,)
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "added", "keyword": keyword}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/keywords/<int:kid>", methods=["DELETE"])
def api_keywords_delete(kid):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("DELETE FROM keywords WHERE id=?", (kid,))
        conn.commit()
        conn.close()
        return jsonify({"status": "deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/keyword-hits")
@db_read
def api_keyword_hits(conn):
    try:
        rows = conn.execute(
            "SELECT id, url, keyword, context, found_at FROM keyword_hits ORDER BY found_at DESC LIMIT 500"
        ).fetchall()
        return jsonify({"count": len(rows), "hits": [dict(r) for r in rows]})
    except sqlite3.OperationalError:
        return jsonify({"count": 0, "hits": []})


# ──────────────────────────────────────────────
#  API: Link Graph
# ──────────────────────────────────────────────

@app.route("/api/link-graph")
@db_read
def api_link_graph(conn):
    c = conn.cursor()
    edges = c.execute("SELECT source_url, target_url FROM link_graph").fetchall()

    # Build nodes from sites + edges
    site_rows = c.execute("SELECT url, category, is_threat FROM sites").fetchall()
    site_map = {r["url"]: dict(r) for r in site_rows}

    all_urls = set()
    for e in edges:
        all_urls.add(e["source_url"])
        all_urls.add(e["target_url"])

    nodes = []
    for url in all_urls:
        info = site_map.get(url, {})
        nodes.append({
            "id": url,
            "category": info.get("category", "unknown"),
            "is_threat": bool(info.get("is_threat", 0)),
            "scanned": url in site_map,
        })

    return jsonify({
        "nodes": nodes,
        "edges": [{"source": e["source_url"], "target": e["target_url"]} for e in edges],
    })


# ──────────────────────────────────────────────
#  API: Stats / Analytics
# ──────────────────────────────────────────────

@app.route("/api/stats")
@db_read
def api_stats(conn):
    c = conn.cursor()

    cats = c.execute(
        "SELECT category, COUNT(*) as count, AVG(score) as avg_score FROM sites GROUP BY category ORDER BY count DESC"
    ).fetchall()

    threat_timeline = c.execute(
        "SELECT DATE(scanned_at) as day, COUNT(*) as count FROM sites WHERE is_threat=1 GROUP BY day ORDER BY day"
    ).fetchall()

    scan_timeline = c.execute(
        "SELECT DATE(scanned_at) as day, COUNT(*) as count FROM sites GROUP BY day ORDER BY day"
    ).fetchall()

    # Top linked pages
    top_linked = c.execute(
        "SELECT target_url, COUNT(*) as incoming FROM link_graph GROUP BY target_url ORDER BY incoming DESC LIMIT 20"
    ).fetchall()

    # Leak stats
    leak_stats = []
    try:
        leak_stats = c.execute(
            "SELECT leak_type, COUNT(*) as count FROM leaks GROUP BY leak_type ORDER BY count DESC"
        ).fetchall()
    except sqlite3.OperationalError:
        pass

    return jsonify({
        "categories": [dict(r) for r in cats],
        "threat_timeline": [dict(r) for r in threat_timeline],
        "scan_timeline": [dict(r) for r in scan_timeline],
        "top_linked_pages": [dict(r) for r in top_linked],
        "leak_stats": [dict(r) for r in leak_stats],
    })


# ──────────────────────────────────────────────
#  API: Search
# ──────────────────────────────────────────────

@app.route("/api/search")
@db_read
def api_search(conn):
    q = request.args.get("q", "").strip()
    if not q or len(q) < 2:
        return jsonify({"error": "Query too short (min 2 chars)"}), 400

    results = []
    c = conn.cursor()

    # Search sites by URL
    url_matches = c.execute(
        "SELECT url, category, score, is_threat, scanned_at FROM sites WHERE url LIKE ? LIMIT 50",
        (f"%{q}%",)
    ).fetchall()
    for r in url_matches:
        results.append({"type": "site", **dict(r)})

    # Search page content
    try:
        content_matches = c.execute(
            "SELECT url, SUBSTR(text_content, 1, 300) as preview FROM page_content WHERE text_content LIKE ? LIMIT 50",
            (f"%{q}%",)
        ).fetchall()
        for r in content_matches:
            results.append({"type": "content", "url": r["url"], "preview": r["preview"]})
    except sqlite3.OperationalError:
        pass

    # Search leaks
    try:
        leak_matches = c.execute(
            "SELECT url, leak_type, leak_value FROM leaks WHERE leak_value LIKE ? LIMIT 50",
            (f"%{q}%",)
        ).fetchall()
        for r in leak_matches:
            results.append({"type": "leak", **dict(r)})
    except sqlite3.OperationalError:
        pass

    return jsonify({"query": q, "count": len(results), "results": results})


# ──────────────────────────────────────────────
#  API: URL Submission
# ──────────────────────────────────────────────

@app.route("/api/scan/submit", methods=["POST"])
def api_submit_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    depth = int(data.get("depth", 0))

    if not url:
        return jsonify({"error": "url is required"}), 400
    if not url.endswith(".onion") and ".onion/" not in url:
        return jsonify({"error": "Only .onion URLs are accepted"}), 400

    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute(
            "INSERT OR IGNORE INTO queue (url, depth, status, discovered_from) VALUES (?, ?, 'pending', 'api_submission')",
            (url, depth)
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "queued", "url": url}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────
#  API: Screenshots
# ──────────────────────────────────────────────

@app.route("/api/screenshot/<url_hash>")
def api_screenshot(url_hash):
    path = os.path.join(DATA_DIR, f"page_{url_hash}.png")
    if not os.path.isfile(path):
        return jsonify({"error": "Screenshot not found"}), 404
    return send_file(path, mimetype="image/png")


@app.route("/api/screenshot-by-url")
@db_read
def api_screenshot_by_url(conn):
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
    path = os.path.join(DATA_DIR, f"page_{url_hash}.png")
    if not os.path.isfile(path):
        return jsonify({"error": "Screenshot not found"}), 404
    return send_file(path, mimetype="image/png")


# ──────────────────────────────────────────────
#  API: Export
# ──────────────────────────────────────────────

@app.route("/api/export/json")
@db_read
def api_export_json(conn):
    c = conn.cursor()
    sites = c.execute("SELECT * FROM sites ORDER BY scanned_at").fetchall()
    queue = c.execute("SELECT * FROM queue").fetchall()

    leaks = []
    try:
        leaks = c.execute("SELECT * FROM leaks ORDER BY found_at").fetchall()
    except sqlite3.OperationalError:
        pass

    kw_hits = []
    try:
        kw_hits = c.execute("SELECT * FROM keyword_hits ORDER BY found_at").fetchall()
    except sqlite3.OperationalError:
        pass

    links = c.execute("SELECT * FROM link_graph").fetchall()

    export = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "sites": [dict(r) for r in sites],
        "queue": [dict(r) for r in queue],
        "leaks": [dict(r) for r in leaks],
        "keyword_hits": [dict(r) for r in kw_hits],
        "link_graph": [dict(r) for r in links],
    }

    return Response(
        json.dumps(export, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=darkai_export.json"},
    )


@app.route("/api/export/csv")
@db_read
def api_export_csv(conn):
    c = conn.cursor()
    sites = c.execute(
        "SELECT url, category, score, is_threat, scanned_at FROM sites ORDER BY scanned_at"
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["url", "category", "score", "is_threat", "scanned_at"])
    for row in sites:
        writer.writerow(list(row))

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=darkai_sites.csv"},
    )


# ──────────────────────────────────────────────
#  API: Scan Sessions
# ──────────────────────────────────────────────

@app.route("/api/sessions")
@db_read
def api_sessions(conn):
    try:
        rows = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT 50"
        ).fetchall()
        return jsonify({"sessions": [dict(r) for r in rows]})
    except sqlite3.OperationalError:
        return jsonify({"sessions": []})


# ──────────────────────────────────────────────
#  API: Alerts Config
# ──────────────────────────────────────────────

@app.route("/api/alerts/config")
def api_alerts_config():
    from alerts import DISCORD_WEBHOOK, SLACK_WEBHOOK, SMTP_HOST
    return jsonify({
        "discord": bool(DISCORD_WEBHOOK),
        "slack": bool(SLACK_WEBHOOK),
        "email": bool(SMTP_HOST),
    })


@app.route("/api/alerts/history")
@db_read
def api_alerts_history(conn):
    try:
        rows = conn.execute(
            "SELECT * FROM alert_log ORDER BY sent_at DESC LIMIT 200"
        ).fetchall()
        return jsonify({"alerts": [dict(r) for r in rows]})
    except sqlite3.OperationalError:
        return jsonify({"alerts": []})


# ──────────────────────────────────────────────
#  Server launcher (called from main.py)
# ──────────────────────────────────────────────

def start_api_server():
    """Start Flask in a daemon thread. Non-blocking."""
    import threading
    log.info(f"Starting API server on {API_HOST}:{API_PORT}")
    t = threading.Thread(
        target=lambda: app.run(
            host=API_HOST,
            port=API_PORT,
            debug=False,
            use_reloader=False,
            threaded=True,
        ),
        daemon=True,
    )
    t.start()
    return t
