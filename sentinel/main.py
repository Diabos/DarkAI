"""
DarkAI — Dark Web Intelligence Crawler
========================================
An AI-powered dark web crawler that scans .onion sites through Tor,
classifies content with zero-shot NLP, detects data leaks, monitors
keywords, maps link graphs, and serves a real-time web dashboard.

Created by Ansh
"""

import sys
import time
import os
import signal
import hashlib
import random
import logging
import sqlite3
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlunparse
from collections import defaultdict
import warnings
warnings.filterwarnings("ignore", message="`resume_download` is deprecated")
import torch
import easyocr
from transformers import pipeline
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from leak_detector import scan_text, get_leak_summary, scan_keywords
import alerts
from api import start_api_server, crawler_state

# ---------------- LOGGING ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sentinel")

# ---------------- CONFIG ----------------
TOR_PROXY    = os.getenv("TOR_PROXY", "socks5://tor-service:9050")
DATA_DIR     = os.getenv("DATA_DIR", "/app/data")
DB_PATH      = os.path.join(DATA_DIR, "crawler.db")
MAX_DEPTH    = int(os.getenv("MAX_DEPTH", "3"))
MAX_SITES    = int(os.getenv("MAX_SITES", "50"))
IDLE_RETRIES = int(os.getenv("IDLE_RETRIES", "3"))
IDLE_WAIT    = int(os.getenv("IDLE_WAIT", "15"))
CRAWL_DELAY  = int(os.getenv("CRAWL_DELAY", "5"))
SEED_URL     = os.getenv("SEED_URL", "").strip()
MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.20"))
MAX_RETRIES  = int(os.getenv("MAX_RETRIES", "2"))
MAX_CONSEC_FAIL = int(os.getenv("MAX_CONSEC_FAIL", "10"))
ALLOWED_SCHEMES = {"http", "https"}

# ── Feature toggles ──
ENABLE_LEAK_DETECTION = os.getenv("ENABLE_LEAK_DETECTION", "true").lower() == "true"
ENABLE_KEYWORD_MONITOR = os.getenv("ENABLE_KEYWORD_MONITOR", "true").lower() == "true"
ENABLE_CHANGE_DETECTION = os.getenv("ENABLE_CHANGE_DETECTION", "true").lower() == "true"
ENABLE_FINGERPRINT_ROTATION = os.getenv("ENABLE_FINGERPRINT_ROTATION", "true").lower() == "true"
ENABLE_API = os.getenv("ENABLE_API", "true").lower() == "true"
API_PORT = int(os.getenv("API_PORT", "5000"))
RANDOM_DELAY_MIN = int(os.getenv("RANDOM_DELAY_MIN", "3"))
RANDOM_DELAY_MAX = int(os.getenv("RANDOM_DELAY_MAX", "8"))
# ----------------------------------------

os.makedirs(DATA_DIR, exist_ok=True)

# ── Startup Banner ──
BANNER = r"""
  ____             _        _    ___
 |  _ \  __ _ _ __| | __   / \  |_ _|
 | | | |/ _` | '__| |/ /  / _ \  | |
 | |_| | (_| | |  |   <  / ___ \ | |
 |____/ \__,_|_|  |_|\_\/_/   \_\___|

  Dark Web Intelligence Platform
  Created by Ansh
"""
log.info(BANNER)

# ── User-Agent Rotation (Fingerprint Avoidance) ──
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
]

# Models loaded lazily
classifier = None
ocr = None


def load_models():
    """Load AI models. Called once after DB init so startup errors are clearer."""
    global classifier, ocr
    log.info("Initializing AI models...")
    classifier = pipeline(
        "zero-shot-classification",
        model="valhalla/distilbart-mnli-12-3",
        device=0 if torch.cuda.is_available() else -1,
        batch_size=8,
    )
    USE_GPU = torch.cuda.is_available()
    ocr = easyocr.Reader(["en"], gpu=USE_GPU)
    log.info("Models loaded successfully.")


# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS queue (
            url TEXT PRIMARY KEY,
            depth INTEGER,
            status TEXT DEFAULT 'pending',
            discovered_from TEXT DEFAULT NULL,
            retries INTEGER DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS sites (
            url TEXT PRIMARY KEY,
            category TEXT,
            score REAL,
            is_threat INTEGER,
            scanned_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS link_graph (
            source_url TEXT,
            target_url TEXT,
            PRIMARY KEY (source_url, target_url)
        )
    """)

    # Page content (search + change detection)
    c.execute("""
        CREATE TABLE IF NOT EXISTS page_content (
            url TEXT PRIMARY KEY,
            text_content TEXT,
            html_hash TEXT,
            screenshot_path TEXT,
            scanned_at TEXT
        )
    """)

    # Data leak findings
    c.execute("""
        CREATE TABLE IF NOT EXISTS leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            leak_type TEXT,
            leak_value TEXT,
            found_at TEXT
        )
    """)

    # Keyword watchlist
    c.execute("""
        CREATE TABLE IF NOT EXISTS keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT UNIQUE,
            added_at TEXT
        )
    """)

    # Keyword hits
    c.execute("""
        CREATE TABLE IF NOT EXISTS keyword_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            keyword TEXT,
            context TEXT,
            found_at TEXT
        )
    """)

    # Scan sessions
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT,
            ended_at TEXT,
            sites_scanned INTEGER DEFAULT 0,
            threats_found INTEGER DEFAULT 0,
            leaks_found INTEGER DEFAULT 0,
            status TEXT DEFAULT 'running'
        )
    """)

    # Alert log
    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            message TEXT,
            url TEXT,
            sent_via TEXT,
            sent_at TEXT
        )
    """)

    # Reset failed URLs under retry cap
    c.execute("UPDATE queue SET status='pending' WHERE status='failed' AND retries < ?", (MAX_RETRIES,))
    conn.commit()
    reset = c.rowcount
    if reset:
        log.info(f"Reset {reset} previously-failed URLs back to pending (under retry cap).")

    # Auto-seed
    if SEED_URL:
        existing = c.execute("SELECT 1 FROM queue WHERE url=?", (SEED_URL,)).fetchone()
        if not existing:
            c.execute("INSERT INTO queue(url, depth, status) VALUES(?, 0, 'pending')", (SEED_URL,))
            conn.commit()
            log.info(f"Auto-seeded starting URL: {SEED_URL}")
        else:
            log.info(f"Seed URL already in queue: {SEED_URL}")

    return conn


# ---------------- HELPERS ----------------
def normalize_url(url):
    url = url.strip()
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return urlunparse(
        (parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, "")
    )


def is_onion(netloc: str) -> bool:
    return netloc.endswith(".onion") or netloc.split(":")[0].endswith(".onion")


def smart_delay():
    """Randomized delay for fingerprint avoidance, or fixed delay."""
    if ENABLE_FINGERPRINT_ROTATION:
        delay = random.uniform(RANDOM_DELAY_MIN, RANDOM_DELAY_MAX)
    else:
        delay = CRAWL_DELAY
    time.sleep(delay)


# ---------------- BROWSER ----------------
def get_browser():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-software-rasterizer")
    options.add_argument("--window-size=1280,900")
    options.add_argument(f"--proxy-server={TOR_PROXY}")

    # Fingerprint avoidance
    if ENABLE_FINGERPRINT_ROTATION:
        ua = random.choice(USER_AGENTS)
        options.add_argument(f"--user-agent={ua}")
        log.debug(f"Browser UA: {ua[:50]}...")

    # Prevent WebRTC IP leaks
    options.add_argument("--disable-webrtc")
    options.add_experimental_option("prefs", {
        "webrtc.ip_handling_policy": "disable_non_proxied_udp",
        "webrtc.multiple_routes_enabled": False,
    })

    try:
        return webdriver.Chrome(options=options)
    except Exception as e:
        log.error(f"Failed to start browser: {e}")
        raise


# ---------------- ANALYSIS ----------------
THREAT_LABELS = [
    "Cryptocurrency Scam",
    "Drug Market",
    "Hacking Service",
    "Phishing",
    "Weapons Market",
    "Human Trafficking",
    "Counterfeit Documents",
    "Ransomware",
    "Stolen Data Market",
    "Malware Distribution",
]
SAFE_LABELS = [
    "Safe Blog",
    "Directory",
    "Search Engine",
    "News Site",
    "Privacy Tool",
    "Forum",
    "Email Service",
    "Whistleblower Platform",
]
ALL_LABELS = THREAT_LABELS + SAFE_LABELS


def analyze_text(text):
    text = text.strip()
    if len(text) < 20:
        return "Unknown", 0.0, False

    result = classifier(text[:1024], ALL_LABELS)
    category = result["labels"][0]
    score = round(result["scores"][0], 2)

    if score < MIN_CONFIDENCE:
        return "Unknown", score, False

    is_threat = category in THREAT_LABELS
    return category, score, is_threat


# ---------------- ALERT LOGGING ----------------
def log_alert(conn, alert_type, message, url, channels):
    if not channels:
        return
    try:
        conn.execute(
            "INSERT INTO alert_log (alert_type, message, url, sent_via, sent_at) VALUES (?, ?, ?, ?, datetime('now'))",
            (alert_type, message[:500], url, ",".join(channels)),
        )
        conn.commit()
    except Exception:
        pass


# ---------------- FEATURE: LEAK DETECTION ----------------
def process_leaks(conn, url, text):
    if not ENABLE_LEAK_DETECTION or not text:
        return 0
    found = scan_text(text)
    if not found:
        return 0

    c = conn.cursor()
    count = 0
    for leak_type, value in found:
        c.execute(
            "INSERT INTO leaks (url, leak_type, leak_value, found_at) VALUES (?, ?, ?, datetime('now'))",
            (url, leak_type, value),
        )
        count += 1
    conn.commit()
    log.info(f"  \u26a0 {count} data leak(s) found on {url}")

    summary = get_leak_summary(found)
    for ltype, values in summary.items():
        channels = alerts.alert_leak(url, ltype, len(values), values[:5])
        log_alert(conn, "leak", f"{len(values)} {ltype}(s)", url, channels)

    return count


# ---------------- FEATURE: KEYWORD MONITORING ----------------
def process_keywords(conn, url, text):
    if not ENABLE_KEYWORD_MONITOR or not text:
        return 0

    c = conn.cursor()
    try:
        kw_rows = c.execute("SELECT keyword FROM keywords").fetchall()
    except sqlite3.OperationalError:
        return 0

    keywords = [r[0] for r in kw_rows]
    if not keywords:
        return 0

    hits = scan_keywords(text, keywords)
    if not hits:
        return 0

    count = 0
    for keyword, snippet in hits:
        c.execute(
            "INSERT INTO keyword_hits (url, keyword, context, found_at) VALUES (?, ?, ?, datetime('now'))",
            (url, keyword, snippet[:500]),
        )
        count += 1
        channels = alerts.alert_keyword(url, keyword, snippet)
        log_alert(conn, "keyword", f'Match: "{keyword}"', url, channels)

    conn.commit()
    log.info(f"  \u2139 {count} keyword hit(s) on {url}")
    return count


# ---------------- FEATURE: CHANGE DETECTION ----------------
def check_content_change(conn, url, text, html_source):
    if not ENABLE_CHANGE_DETECTION or not html_source:
        return False

    new_hash = hashlib.sha256(html_source.encode("utf-8", errors="replace")).hexdigest()
    c = conn.cursor()

    try:
        old = c.execute("SELECT html_hash FROM page_content WHERE url=?", (url,)).fetchone()
    except sqlite3.OperationalError:
        return False

    changed = False
    if old and old[0] and old[0] != new_hash:
        changed = True
        log.info(f"  \u2139 Content changed: {url}")
        channels = alerts.alert_site_change(url, old[0], new_hash)
        log_alert(conn, "change", "Content changed", url, channels)

    url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
    screenshot_path = f"page_{url_hash}.png"
    c.execute(
        "INSERT OR REPLACE INTO page_content (url, text_content, html_hash, screenshot_path, scanned_at) VALUES (?, ?, ?, ?, datetime('now'))",
        (url, text[:10000] if text else "", new_hash, screenshot_path),
    )
    conn.commit()
    return changed


# ---------------- PRETTY PRINT ----------------
def print_scan_result(idx, url, category, score, threat, depth, new_links, leaks_found=0, kw_hits=0):
    flag = "!! THREAT" if threat else "   safe  "
    extras = []
    if leaks_found:
        extras.append(f"{leaks_found} leaks")
    if kw_hits:
        extras.append(f"{kw_hits} keyword hits")
    extra_str = f"  |  {', '.join(extras)}" if extras else ""
    log.info(
        f"\n{'='*70}\n"
        f"  [{idx}] {url}\n"
        f"      depth={depth}  |  category={category}  |  score={score}  |  {flag}\n"
        f"      +{new_links} new links queued{extra_str}\n"
        f"{'='*70}"
    )


def print_summary(conn, session_id=None):
    c = conn.cursor()

    sites = c.execute(
        "SELECT url, category, score, is_threat, scanned_at FROM sites ORDER BY scanned_at"
    ).fetchall()

    threats  = [s for s in sites if s[3]]
    safe     = [s for s in sites if not s[3]]

    cats = defaultdict(int)
    for s in sites:
        cats[s[1]] += 1

    pending = c.execute("SELECT COUNT(*) FROM queue WHERE status='pending'").fetchone()[0]
    visited = c.execute("SELECT COUNT(*) FROM queue WHERE status='visited'").fetchone()[0]
    failed  = c.execute("SELECT COUNT(*) FROM queue WHERE status='failed'").fetchone()[0]

    total_leaks = 0
    try:
        total_leaks = c.execute("SELECT COUNT(*) FROM leaks").fetchone()[0]
    except sqlite3.OperationalError:
        pass

    total_kw_hits = 0
    try:
        total_kw_hits = c.execute("SELECT COUNT(*) FROM keyword_hits").fetchone()[0]
    except sqlite3.OperationalError:
        pass

    link_rows = c.execute("SELECT source_url, target_url FROM link_graph ORDER BY source_url").fetchall()
    link_map = defaultdict(list)
    for src, tgt in link_rows:
        link_map[src].append(tgt)

    site_info = {}
    for url, cat, score, threat, ts in sites:
        site_info[url] = (cat, score, bool(threat))

    W = 80
    LINE  = "=" * W
    THIN  = "-" * W

    ICON_OK      = "\u2714"
    ICON_FAIL    = "\u2716"
    ICON_BULLET  = "\u2022"
    ICON_WARN    = "\u26a0"
    BOX_TOP      = "\u250c"
    BOX_PIPE     = "\u2502"
    BOX_TEE      = "\u251c"
    BOX_END      = "\u2514"
    BOX_H        = "\u2500"
    BAR_FULL     = "\u2588"
    BAR_EMPTY    = "\u2591"
    THREAT_HEADER = f"{ICON_WARN}  THREATS DETECTED  {ICON_WARN}"

    out = []
    out.append(f"\n\n{LINE}")
    out.append(f"{'':^{W}}")
    out.append(f"{'D A R K A I   \u2014   C R A W L   S U M M A R Y':^{W}}")
    out.append(f"{'':^{W}}")
    out.append(LINE)

    out.append(f"\n  {'OVERVIEW':^{W-2}}")
    out.append(f"  {THIN}")
    out.append(f"  | {'Total sites scanned':.<40} {len(sites):>5} |")
    out.append(f"  | {'Threats found':.<40} {len(threats):>5} |")
    out.append(f"  | {'Safe sites':.<40} {len(safe):>5} |")
    out.append(f"  | {'Data leaks detected':.<40} {total_leaks:>5} |")
    out.append(f"  | {'Keyword hits':.<40} {total_kw_hits:>5} |")
    out.append(f"  | {'Queue visited':.<40} {visited:>5} |")
    out.append(f"  | {'Queue pending':.<40} {pending:>5} |")
    out.append(f"  | {'Queue failed':.<40} {failed:>5} |")
    out.append(f"  {THIN}")

    if cats:
        out.append(f"\n  {'CATEGORIES':^{W-2}}")
        out.append(f"  {THIN}")
        max_count = max(cats.values()) if cats else 1
        bar_max = 30
        for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
            bar_len = max(1, int((count / max_count) * bar_max))
            bar = BAR_FULL * bar_len
            out.append(f"  | {cat:.<30} {bar} {count}")
        out.append(f"  {THIN}")

    if threats:
        out.append(f"\n  {THREAT_HEADER:^{W-2}}")
        out.append(f"  {THIN}")
        for url, cat, score, _, ts in threats:
            out.append(f"  | !! [{score:.2f}] {cat:25s}  {url}")
        out.append(f"  {THIN}")

    if total_leaks > 0:
        try:
            leak_summary = c.execute(
                "SELECT leak_type, COUNT(*) as cnt FROM leaks GROUP BY leak_type ORDER BY cnt DESC"
            ).fetchall()
            out.append(f"\n  {'DATA LEAKS DETECTED':^{W-2}}")
            out.append(f"  {THIN}")
            for ltype, cnt in leak_summary:
                out.append(f"  | {ltype:.<35} {cnt:>5}")
            out.append(f"  {THIN}")
        except sqlite3.OperationalError:
            pass

    out.append(f"\n  {'SITE LIST':^{W-2}}")
    out.append(f"  {THIN}")
    out.append(f"  {'#':>4}  {'Category':20s}  {'Score':>6}  {'Threat':>6}  {'URL'}")
    out.append(f"  {'----':>4}  {'--------------------':20s}  {'------':>6}  {'------':>6}  {'----------------------------------------'}")
    for i, (url, cat, score, threat, ts) in enumerate(sites, 1):
        t_mark = "  YES" if threat else "   no"
        icon = ICON_FAIL if threat else ICON_OK
        out.append(f"  {i:>4}  {cat:20s}  {score:>6.2f}  {t_mark:>6}  {icon} {url}")
    out.append(f"  {THIN}")

    if link_map:
        out.append(f"\n  {'LINK MAP  (page -> discovered URLs)':^{W-2}}")
        out.append(f"  {THIN}")
        for source_url in dict.fromkeys(s[0] for s in sites if s[0] in link_map):
            targets = link_map[source_url]
            src_cat = site_info.get(source_url, ("?",))[0]
            out.append("")
            out.append(f"  {BOX_TOP}{BOX_H} [{src_cat}] {source_url}")
            out.append(f"  {BOX_PIPE}   Found {len(targets)} link(s):")
            for j, tgt in enumerate(targets):
                is_last = (j == len(targets) - 1)
                branch = BOX_END if is_last else BOX_TEE
                tgt_info = site_info.get(tgt)
                if tgt_info:
                    tgt_cat, tgt_score, tgt_threat = tgt_info
                    status_icon = ICON_FAIL if tgt_threat else ICON_OK
                    out.append(f"  {BOX_PIPE}   {branch}{BOX_H}{BOX_H} {status_icon} {tgt}  ({tgt_cat}, {tgt_score:.2f})")
                else:
                    out.append(f"  {BOX_PIPE}   {branch}{BOX_H}{BOX_H} {ICON_BULLET} {tgt}  (not scanned)")
            out.append(f"  {BOX_PIPE}")
        out.append(f"  {THIN}")

    bar = BAR_FULL * 50
    out.append(f"\n  Progress: |{bar}| 100.0% Complete")
    cap_str = str(MAX_SITES) if MAX_SITES > 0 else "unlimited"
    depth_str = str(MAX_DEPTH) if MAX_DEPTH > 0 else "unlimited"
    out.append(f"  ({len(sites)} sites scanned, cap={cap_str}, depth={depth_str}, {pending} still pending)")

    out.append(f"\n  {'FEATURES ACTIVE':^{W-2}}")
    out.append(f"  {THIN}")
    features = [
        ("Leak Detection", ENABLE_LEAK_DETECTION),
        ("Keyword Monitor", ENABLE_KEYWORD_MONITOR),
        ("Change Detection", ENABLE_CHANGE_DETECTION),
        ("Fingerprint Rotation", ENABLE_FINGERPRINT_ROTATION),
        ("Web Dashboard", ENABLE_API),
        ("Alert System", alerts.has_any_channel()),
    ]
    for fname, enabled in features:
        status = ICON_OK + " ON" if enabled else ICON_FAIL + " OFF"
        out.append(f"  | {fname:.<35} {status}")
    if ENABLE_API:
        out.append(f"  | {'Dashboard URL':.<35} http://localhost:{API_PORT}")
    out.append(f"  {THIN}")

    out.append(f"\n{LINE}\n")

    summary_text = "\n".join(out)
    log.info(summary_text)

    report_path = os.path.join(DATA_DIR, "report.txt")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(summary_text.lstrip("\n"))
        log.info(f"Report saved to {report_path}")
    except Exception as e:
        log.warning(f"Could not save report: {e}")

    if session_id:
        try:
            c.execute(
                "UPDATE scan_sessions SET ended_at=datetime('now'), sites_scanned=?, threats_found=?, leaks_found=?, status='completed' WHERE id=?",
                (len(sites), len(threats), total_leaks, session_id),
            )
            conn.commit()
        except Exception:
            pass


# ---------------- TOR READINESS ----------------
def wait_for_tor(max_attempts=10, interval=5):
    for attempt in range(1, max_attempts + 1):
        try:
            driver = get_browser()
            driver.set_page_load_timeout(30)
            driver.get("about:blank")
            log.info(f"Tor proxy is ready (attempt {attempt}/{max_attempts}).")
            return driver
        except Exception as e:
            log.warning(f"Tor not ready (attempt {attempt}/{max_attempts}): {e}")
            try:
                driver.quit()
            except Exception:
                pass
            if attempt < max_attempts:
                time.sleep(interval)
    raise RuntimeError(f"Tor proxy not reachable after {max_attempts} attempts.")


# ---------------- CRAWLER ----------------
def crawl():
    conn = init_db()
    load_models()

    # Start web dashboard API
    if ENABLE_API:
        start_api_server()
        log.info(f"\u2139 Web dashboard: http://localhost:{API_PORT}")

    c = conn.cursor()
    driver = None
    running = True
    scan_count = 0
    idle_count = 0
    consec_fail = 0
    session_id = None

    # Create scan session
    try:
        c.execute("INSERT INTO scan_sessions (started_at, status) VALUES (datetime('now'), 'running')")
        conn.commit()
        session_id = c.lastrowid
    except Exception:
        pass

    crawler_state["status"] = "starting"
    crawler_state["start_time"] = datetime.utcnow()

    def shutdown_handler(signum, frame):
        nonlocal running
        log.info("Shutting down gracefully...")
        running = False

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    if len(sys.argv) > 1:
        seed = normalize_url(sys.argv[1])
        c.execute("INSERT OR IGNORE INTO queue (url, depth) VALUES (?, 0)", (seed,))
        conn.commit()
        log.info(f"Seed added: {seed}")

    try:
        driver = wait_for_tor()
        crawler_state["status"] = "running"

        while running:
            c.execute("SELECT url, depth FROM queue WHERE status='pending' LIMIT 1")
            row = c.fetchone()

            if not row:
                idle_count += 1
                remaining = IDLE_RETRIES - idle_count
                crawler_state["status"] = "idle"
                if idle_count >= IDLE_RETRIES:
                    log.info(f"Queue empty after {IDLE_RETRIES} retries \u2014 finishing crawl.")
                    break
                log.info(f"Queue empty, retrying in {IDLE_WAIT}s  ({remaining} retries left)...")
                time.sleep(IDLE_WAIT)
                continue

            idle_count = 0
            url, depth = row
            crawler_state["status"] = "running"
            crawler_state["current_url"] = url

            url_scheme = urlparse(url).scheme.lower()
            if url_scheme not in ALLOWED_SCHEMES:
                log.warning(f"Skipping disallowed scheme '{url_scheme}': {url}")
                c.execute("UPDATE queue SET status='failed' WHERE url=?", (url,))
                conn.commit()
                continue

            scan_count += 1
            crawler_state["scan_count"] = scan_count
            if MAX_SITES > 0 and scan_count > MAX_SITES:
                log.info(f"Reached MAX_SITES={MAX_SITES} \u2014 finishing crawl.")
                break

            cap_label = f"{scan_count}/{MAX_SITES}" if MAX_SITES > 0 else f"{scan_count}"
            log.info(f"[{cap_label}] Crawling: {url}  (depth={depth})")

            try:
                driver.set_page_load_timeout(60)
                driver.get(url)

                WebDriverWait(driver, 20).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )

                url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
                screenshot = os.path.join(DATA_DIR, f"page_{url_hash}.png")
                driver.save_screenshot(screenshot)

                # OCR + Classification
                text = " ".join(ocr.readtext(screenshot, detail=0))
                category, score, threat = analyze_text(text)

                c.execute(
                    "INSERT OR REPLACE INTO sites VALUES (?, ?, ?, ?, datetime('now'))",
                    (url, category, score, int(threat)),
                )

                # Get HTML for deeper analysis
                html_source = ""
                try:
                    html_source = driver.page_source
                except Exception:
                    pass

                # Extract visible text from HTML (richer than OCR)
                page_text = text
                if html_source:
                    try:
                        soup_text = BeautifulSoup(html_source, "html.parser")
                        visible_text = soup_text.get_text(separator=" ", strip=True)
                        if len(visible_text) > len(text):
                            page_text = visible_text
                    except Exception:
                        pass

                # ── Data Leak Detection ──
                leaks_found = process_leaks(conn, url, page_text)

                # ── Keyword Monitoring ──
                kw_hits = process_keywords(conn, url, page_text)

                # ── Content Change Detection ──
                check_content_change(conn, url, page_text, html_source)

                # ── Threat Alerts ──
                if threat and alerts.has_any_channel():
                    channels = alerts.alert_threat(url, category, score)
                    log_alert(conn, "threat", f"{category} ({score:.0%})", url, channels)

                # ── Link Extraction ──
                new_links = 0
                if MAX_DEPTH == 0 or depth < MAX_DEPTH:
                    soup = BeautifulSoup(html_source or driver.page_source, "html.parser")
                    for a in soup.find_all("a", href=True):
                        new_url = normalize_url(urljoin(url, a["href"]))
                        parsed = urlparse(new_url)

                        if parsed.scheme.lower() in ALLOWED_SCHEMES and is_onion(parsed.netloc):
                            c.execute(
                                "INSERT OR IGNORE INTO link_graph (source_url, target_url) VALUES (?, ?)",
                                (url, new_url),
                            )
                            res = c.execute(
                                "INSERT OR IGNORE INTO queue (url, depth, discovered_from) VALUES (?, ?, ?)",
                                (new_url, depth + 1, url),
                            )
                            if res.rowcount:
                                new_links += 1

                c.execute("UPDATE queue SET status='visited' WHERE url=?", (url,))
                conn.commit()

                print_scan_result(scan_count, url, category, score, threat, depth, new_links, leaks_found, kw_hits)

                consec_fail = 0
                crawler_state["consec_fail"] = 0

                smart_delay()

            except Exception as e:
                c.execute("UPDATE queue SET status='failed', retries=retries+1 WHERE url=?", (url,))
                conn.commit()
                log.warning(f"Failed on {url}: {e}")

                consec_fail += 1
                crawler_state["consec_fail"] = consec_fail
                if consec_fail >= MAX_CONSEC_FAIL:
                    log.error(f"{MAX_CONSEC_FAIL} consecutive failures \u2014 aborting crawl.")
                    break

                try:
                    driver.title
                except Exception:
                    log.warning("Browser crashed, restarting...")
                    try:
                        driver.quit()
                    except Exception:
                        pass
                    driver = get_browser()

                retry_count = c.execute("SELECT retries FROM queue WHERE url=?", (url,)).fetchone()[0]
                if retry_count <= MAX_RETRIES:
                    c.execute("UPDATE queue SET status='pending' WHERE url=?", (url,))
                    conn.commit()
                    scan_count -= 1
                    log.info(f"Re-queued {url} for retry ({retry_count}/{MAX_RETRIES}).")
                else:
                    log.info(f"Giving up on {url} after {MAX_RETRIES} retries.")

    finally:
        crawler_state["status"] = "finished"
        crawler_state["current_url"] = None

        try:
            if conn:
                print_summary(conn, session_id)
        except Exception as e:
            log.warning(f"Could not print summary: {e}")

        log.info("Cleaning up...")
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        if conn:
            conn.close()
        log.info("Shutdown complete.")

        # Keep alive for dashboard after crawl ends
        if ENABLE_API:
            log.info(f"Dashboard still running at http://localhost:{API_PORT}")
            log.info("Press Ctrl+C to exit.")
            try:
                while True:
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                log.info("Exiting.")


if __name__ == "__main__":
    crawl()
