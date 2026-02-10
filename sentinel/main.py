import sys
import time
import os
import sqlite3
from urllib.parse import urljoin, urlparse

import torch
import easyocr
from transformers import pipeline
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


# ---------------- CONFIG ----------------
TOR_PROXY = os.getenv("TOR_PROXY", "socks5://tor-service:9050")
DATA_DIR = "/app/data"
DB_PATH = os.path.join(DATA_DIR, "crawler.db")
MAX_DEPTH = 3
# ----------------------------------------

os.makedirs(DATA_DIR, exist_ok=True)

print("[*] Initializing AI models")

classifier = pipeline(
    "zero-shot-classification",
    model="valhalla/distilbart-mnli-12-3",
    device=0 if torch.cuda.is_available() else -1
)

ocr = easyocr.Reader(["en"], gpu=False)


# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS queue (
            url TEXT PRIMARY KEY,
            depth INTEGER,
            status TEXT DEFAULT 'pending'
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

    conn.commit()
    return conn


# ---------------- BROWSER ----------------
def get_browser():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"--proxy-server={TOR_PROXY}")
    return webdriver.Chrome(options=options)


# ---------------- ANALYSIS ----------------
def analyze_text(text):
    if len(text) < 20:
        return "Unknown", 0.0, False

    labels = [
        "Cryptocurrency Scam",
        "Drug Market",
        "Hacking Service",
        "Phishing",
        "Safe Blog",
        "Directory",
        "Search Engine"
    ]

    result = classifier(text[:1024], labels)
    category = result["labels"][0]
    score = round(result["scores"][0], 2)
    is_threat = category in labels[:4]

    return category, score, is_threat


# ---------------- CRAWLER ----------------
def crawl():
    conn = init_db()
    c = conn.cursor()

    # ---- Manual Injection ----
    if len(sys.argv) > 1:
        seed = sys.argv[1]
        c.execute(
            "INSERT OR IGNORE INTO queue (url, depth) VALUES (?, 0)",
            (seed,)
        )
        conn.commit()
        print(f"[+] Seed added: {seed}")

    driver = get_browser()

    while True:
        c.execute("SELECT url, depth FROM queue WHERE status='pending' LIMIT 1")
        row = c.fetchone()

        if not row:
            time.sleep(30)
            continue

        url, depth = row
        base_host = urlparse(url).netloc

        print(f"[>] Crawling {url} (depth={depth})")

        try:
            driver.set_page_load_timeout(60)
            driver.get(url)

            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            screenshot = os.path.join(DATA_DIR, "page.png")
            driver.save_screenshot(screenshot)

            text = " ".join(ocr.readtext(screenshot, detail=0))
            category, score, threat = analyze_text(text)

            c.execute("""
                INSERT OR REPLACE INTO sites
                VALUES (?, ?, ?, ?, datetime('now'))
            """, (url, category, score, int(threat)))

            # ---- Link Extraction ----
            if depth < MAX_DEPTH:
                soup = BeautifulSoup(driver.page_source, "html.parser")
                for a in soup.find_all("a", href=True):
                    new_url = urljoin(url, a["href"])
                    parsed = urlparse(new_url)

                    if ".onion" in parsed.netloc and parsed.netloc == base_host:
                        c.execute(
                            "INSERT OR IGNORE INTO queue (url, depth) VALUES (?, ?)",
                            (new_url, depth + 1)
                        )

            c.execute("UPDATE queue SET status='visited' WHERE url=?", (url,))
            conn.commit()

            print(f"[✓] {category} | Threat={threat}")

        except Exception as e:
            c.execute("UPDATE queue SET status='failed' WHERE url=?", (url,))
            conn.commit()
            print(f"[!] Failed: {e}")


if __name__ == "__main__":
    time.sleep(10)
    crawl()