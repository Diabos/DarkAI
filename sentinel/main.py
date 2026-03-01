import sys
import time
import os
import signal
import hashlib
import logging
import sqlite3
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
CRAWL_DELAY  = int(os.getenv("CRAWL_DELAY", "5"))   # seconds between requests
SEED_URL     = os.getenv("SEED_URL", "").strip()       # auto-inject starting URL
MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", "0.20"))  # below this → "Unknown"
MAX_RETRIES  = int(os.getenv("MAX_RETRIES", "2"))     # per-URL retry cap
MAX_CONSEC_FAIL = int(os.getenv("MAX_CONSEC_FAIL", "10"))  # consecutive failures before abort
ALLOWED_SCHEMES = {"http", "https"}
# ----------------------------------------

os.makedirs(DATA_DIR, exist_ok=True)

# ── Startup Banner ──
BANNER = r"""
  ____             _        _    ___
 |  _ \  __ _ _ __| | __   / \  |_ _|
 | | | |/ _` | '__| |/ /  / _ \  | |
 | |_| | (_| | |  |   <  / ___ \ | |
 |____/ \__,_|_|  |_|\_\/_/   \_\___|

  Created by Ansh
"""
log.info(BANNER)

# Models are loaded lazily so the DB is initialized first
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
    conn.execute("PRAGMA journal_mode=WAL")  # safer for crashes
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

    # Link graph: tracks every link found on every page
    c.execute("""
        CREATE TABLE IF NOT EXISTS link_graph (
            source_url TEXT,
            target_url TEXT,
            PRIMARY KEY (source_url, target_url)
        )
    """)

    # On (re)start, reset failed URLs that haven't exceeded retry cap.
    # 'visited' URLs stay visited — they won't be re-scanned.
    c.execute("UPDATE queue SET status='pending' WHERE status='failed' AND retries < ?", (MAX_RETRIES,))
    conn.commit()
    reset = c.rowcount
    if reset:
        log.info(f"Reset {reset} previously-failed URLs back to pending (under retry cap).")

    # Auto-seed: if SEED_URL is set and not already in queue, insert it
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
    """Strip fragments, trailing whitespace, and trailing slashes to reduce duplicates."""
    url = url.strip()
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return urlunparse(
        (parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, "")
    )


def is_onion(netloc: str) -> bool:
    """Validate that a netloc is a proper .onion address."""
    return netloc.endswith(".onion") or netloc.split(":")[0].endswith(".onion")


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
]
SAFE_LABELS = [
    "Safe Blog",
    "Directory",
    "Search Engine",
]
ALL_LABELS = THREAT_LABELS + SAFE_LABELS


def analyze_text(text):
    text = text.strip()
    if len(text) < 20:
        return "Unknown", 0.0, False

    result = classifier(text[:1024], ALL_LABELS)
    category = result["labels"][0]
    score = round(result["scores"][0], 2)

    # Low-confidence results are unreliable — label as Unknown
    if score < MIN_CONFIDENCE:
        return "Unknown", score, False

    is_threat = category in THREAT_LABELS
    return category, score, is_threat


# ---------------- PRETTY PRINT ----------------
def print_scan_result(idx, url, category, score, threat, depth, new_links):
    """Live per-page output printed right after each scan."""
    flag = "!! THREAT" if threat else "   safe  "
    log.info(
        f"\n{'='*70}\n"
        f"  [{idx}] {url}\n"
        f"      depth={depth}  |  category={category}  |  score={score}  |  {flag}\n"
        f"      +{new_links} new links queued\n"
        f"{'='*70}"
    )


def print_summary(conn):
    """Final summary printed once the crawl session is over."""
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

    # Build link graph data
    link_rows = c.execute("SELECT source_url, target_url FROM link_graph ORDER BY source_url").fetchall()
    link_map = defaultdict(list)
    for src, tgt in link_rows:
        link_map[src].append(tgt)

    # Build site lookup for quick category/threat info
    site_info = {}
    for url, cat, score, threat, ts in sites:
        site_info[url] = (cat, score, bool(threat))

    W = 80
    LINE  = "=" * W
    THIN  = "-" * W

    # Pre-compute unicode strings (Python 3.10 can't use \u inside f-string expressions)
    ICON_OK      = "\u2714"  # ✔
    ICON_FAIL    = "\u2716"  # ✖
    ICON_BULLET  = "\u2022"  # •
    ICON_WARN    = "\u26a0"  # ⚠
    BOX_TOP      = "\u250c"  # ┌
    BOX_PIPE     = "\u2502"  # │
    BOX_TEE      = "\u251c"  # ├
    BOX_END      = "\u2514"  # └
    BOX_H        = "\u2500"  # ─
    BAR_FULL     = "\u2588"  # █
    BAR_EMPTY    = "\u2591"  # ░
    THREAT_HEADER = f"{ICON_WARN}  THREATS DETECTED  {ICON_WARN}"

    out = []
    out.append(f"\n\n{LINE}")
    out.append(f"{'':^{W}}")
    out.append(f"{'C R A W L   S U M M A R Y':^{W}}")
    out.append(f"{'':^{W}}")
    out.append(LINE)

    # ── Overview ──
    out.append(f"\n  {'OVERVIEW':^{W-2}}")
    out.append(f"  {THIN}")
    out.append(f"  | {'Total sites scanned':.<40} {len(sites):>5} |")
    out.append(f"  | {'Threats found':.<40} {len(threats):>5} |")
    out.append(f"  | {'Safe sites':.<40} {len(safe):>5} |")
    out.append(f"  | {'Queue visited':.<40} {visited:>5} |")
    out.append(f"  | {'Queue pending':.<40} {pending:>5} |")
    out.append(f"  | {'Queue failed':.<40} {failed:>5} |")
    out.append(f"  {THIN}")

    # ── Category Breakdown (bar chart style) ──
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

    # ── Threats ──
    if threats:
        out.append(f"\n  {THREAT_HEADER:^{W-2}}")
        out.append(f"  {THIN}")
        for url, cat, score, _, ts in threats:
            out.append(f"  | !! [{score:.2f}] {cat:25s}  {url}")
        out.append(f"  {THIN}")

    # ── Site List ──
    out.append(f"\n  {'SITE LIST':^{W-2}}")
    out.append(f"  {THIN}")
    out.append(f"  {'#':>4}  {'Category':20s}  {'Score':>6}  {'Threat':>6}  {'URL'}")
    out.append(f"  {'----':>4}  {'--------------------':20s}  {'------':>6}  {'------':>6}  {'----------------------------------------'}")
    for i, (url, cat, score, threat, ts) in enumerate(sites, 1):
        t_mark = "  YES" if threat else "   no"
        icon = ICON_FAIL if threat else ICON_OK
        out.append(f"  {i:>4}  {cat:20s}  {score:>6.2f}  {t_mark:>6}  {icon} {url}")
    out.append(f"  {THIN}")

    # ── Link Map / Directory Contents ──
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

    # ── Progress bar (100% when crawl finishes, regardless of reason) ──
    bar = BAR_FULL * 50
    out.append(f"\n  Progress: |{bar}| 100.0% Complete")
    cap_str = str(MAX_SITES) if MAX_SITES > 0 else "unlimited"
    depth_str = str(MAX_DEPTH) if MAX_DEPTH > 0 else "unlimited"
    out.append(f"  ({len(sites)} sites scanned, cap={cap_str}, depth={depth_str}, {pending} still pending)")

    out.append(f"\n{LINE}\n")

    summary_text = "\n".join(out)
    log.info(summary_text)

    # ── Save report to file ──
    report_path = os.path.join(DATA_DIR, "report.txt")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(summary_text.lstrip("\n"))
        log.info(f"Report saved to {report_path}")
    except Exception as e:
        log.warning(f"Could not save report: {e}")


# ---------------- TOR READINESS ----------------
def wait_for_tor(max_attempts=10, interval=5):
    """Try to start a browser through Tor. Retries until Tor is ready."""
    for attempt in range(1, max_attempts + 1):
        try:
            driver = get_browser()
            # Quick connectivity test through Tor
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
    load_models()  # load AI models after DB is ready
    c = conn.cursor()
    driver = None
    running = True
    scan_count = 0
    idle_count = 0        # consecutive empty-queue checks
    consec_fail = 0       # consecutive failures (reset on any success)

    def shutdown_handler(signum, frame):
        nonlocal running
        log.info("Shutting down gracefully...")
        running = False

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # ---- Manual Injection ----
    if len(sys.argv) > 1:
        seed = normalize_url(sys.argv[1])
        c.execute(
            "INSERT OR IGNORE INTO queue (url, depth) VALUES (?, 0)",
            (seed,),
        )
        conn.commit()
        log.info(f"Seed added: {seed}")

    try:
        driver = wait_for_tor()  # retry until Tor is up

        while running:
            # ---- Pick next URL ----
            c.execute("SELECT url, depth FROM queue WHERE status='pending' LIMIT 1")
            row = c.fetchone()

            if not row:
                idle_count += 1
                remaining = IDLE_RETRIES - idle_count
                if idle_count >= IDLE_RETRIES:
                    log.info(f"Queue empty after {IDLE_RETRIES} retries — finishing crawl.")
                    break
                log.info(f"Queue empty, retrying in {IDLE_WAIT}s  ({remaining} retries left)...")
                time.sleep(IDLE_WAIT)
                continue

            # Reset idle counter as soon as we have work
            idle_count = 0
            url, depth = row

            # Validate URL scheme before navigating (block file://, javascript:, data:, etc.)
            url_scheme = urlparse(url).scheme.lower()
            if url_scheme not in ALLOWED_SCHEMES:
                log.warning(f"Skipping disallowed scheme '{url_scheme}': {url}")
                c.execute("UPDATE queue SET status='failed' WHERE url=?", (url,))
                conn.commit()
                continue

            scan_count += 1
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

                text = " ".join(ocr.readtext(screenshot, detail=0))
                category, score, threat = analyze_text(text)

                c.execute(
                    "INSERT OR REPLACE INTO sites VALUES (?, ?, ?, ?, datetime('now'))",
                    (url, category, score, int(threat)),
                )

                # ---- Link Extraction (chain crawling) ----
                new_links = 0
                if MAX_DEPTH == 0 or depth < MAX_DEPTH:
                    soup = BeautifulSoup(driver.page_source, "html.parser")
                    for a in soup.find_all("a", href=True):
                        new_url = normalize_url(urljoin(url, a["href"]))
                        parsed = urlparse(new_url)

                        # Follow ANY .onion link — not just same-host
                        # Also validate scheme to block javascript:/data:/file: links
                        if parsed.scheme.lower() in ALLOWED_SCHEMES and is_onion(parsed.netloc):
                            # Record in link graph (always, even if URL already queued)
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

                print_scan_result(scan_count, url, category, score, threat, depth, new_links)

                # Success — reset consecutive failure counter
                consec_fail = 0

                # Polite crawl delay to avoid overloading Tor / targets
                if CRAWL_DELAY > 0:
                    time.sleep(CRAWL_DELAY)

            except Exception as e:
                c.execute("UPDATE queue SET status='failed', retries=retries+1 WHERE url=?", (url,))
                conn.commit()
                log.warning(f"Failed on {url}: {e}")

                consec_fail += 1
                if consec_fail >= MAX_CONSEC_FAIL:
                    log.error(f"{MAX_CONSEC_FAIL} consecutive failures \u2014 aborting crawl (possible Tor/network issue).")
                    break

                # Recreate browser if it crashed
                try:
                    driver.title  # quick health check
                except Exception:
                    log.warning("Browser crashed, restarting...")
                    try:
                        driver.quit()
                    except Exception:
                        pass
                    driver = get_browser()

                # Re-queue ONLY if under per-URL retry cap
                retry_count = c.execute("SELECT retries FROM queue WHERE url=?", (url,)).fetchone()[0]
                if retry_count <= MAX_RETRIES:
                    c.execute("UPDATE queue SET status='pending' WHERE url=?", (url,))
                    conn.commit()
                    scan_count -= 1  # don't count the failed attempt
                    log.info(f"Re-queued {url} for retry ({retry_count}/{MAX_RETRIES}).")
                else:
                    log.info(f"Giving up on {url} after {MAX_RETRIES} retries.")

    finally:
        # Always print summary, even on SIGTERM / exceptions
        try:
            if conn:
                print_summary(conn)
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


if __name__ == "__main__":
    crawl()