# DarkAI

**AI-powered dark web crawler & threat analyzer.**

DarkAI crawls `.onion` websites through the Tor network and classifies each page as safe or malicious using Computer Vision (OCR) and Natural Language Processing (NLP). Unlike traditional scrapers that rely on HTML parsing, DarkAI analyzes visually rendered content — making it effective against JavaScript-heavy pages, obfuscated text, and image-based content.

---

## Features

- **Anonymous crawling** — all traffic routed through Tor (SOCKS5 proxy)
- **Visual analysis** — screenshots every page, extracts text with EasyOCR
- **AI classification** — zero-shot NLP (DistilBART) categorizes pages as threats or safe
- **Infinite chain crawling** — follows `.onion` links across domains with no depth/site limits (configurable)
- **Anti-dead-state** — per-URL retry caps, consecutive failure breaker, idle detection
- **Link map** — tracks which page discovered which URLs (full graph stored in SQLite)
- **Beautiful summary** — category bar charts, tree-view link map, threat alerts, saved to `report.txt`
- **Dockerized** — one command to build & run, zero setup
- **Model caching** — AI models (~100 MB) persist across runs via Docker volumes

---

## Architecture

```
                    ┌─────────────────────┐
                    │   docker-compose    │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼                              ▼
     ┌─────────────────┐          ┌──────────────────────┐
     │   tor-service    │◄────────│     sentinel-ai       │
     │  (SOCKS5 proxy)  │  9050   │   (Python crawler)    │
     │  osminogin/tor   │         │                        │
     └─────────────────┘          │  Selenium + Chromium   │
                                  │  EasyOCR (vision)      │
                                  │  DistilBART (NLP)      │
                                  │  SQLite (storage)      │
                                  └──────────────────────┘
```

**Crawl loop:**
1. Pick next pending URL from SQLite queue
2. Load page via headless Chromium through Tor
3. Take screenshot → extract text with EasyOCR
4. Classify text with zero-shot NLP → threat or safe
5. Extract all `.onion` links from HTML → add to queue
6. Record results + link graph in SQLite
7. Repeat until queue is empty or limits reached

---

## Quick Start

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

```bash
git clone https://github.com/YOUR_USERNAME/DarkAI.git
cd DarkAI
docker compose up --build -d
```

That's it. The seed URL is pre-configured. Watch the crawl:

```bash
docker logs -f sentinel-ai
```

The crawler will:
1. Wait for Tor to be healthy (automatic healthcheck)
2. Auto-inject the seed URL
3. Download AI models (~100 MB, cached for future runs)
4. Crawl, classify, and print results per page
5. Print a full summary and save `sentinel/data/report.txt`
6. Exit cleanly

---

## Configuration

All settings are environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `SEED_URL` | *(pre-configured)* | Starting `.onion` URL to crawl |
| `MAX_DEPTH` | `0` | Max link-hop depth (`0` = unlimited) |
| `MAX_SITES` | `0` | Max pages to scan (`0` = unlimited) |
| `CRAWL_DELAY` | `5` | Seconds between requests |
| `MAX_RETRIES` | `2` | Per-URL retry cap before giving up |
| `MAX_CONSEC_FAIL` | `10` | Consecutive failures before aborting |
| `IDLE_RETRIES` | `3` | Empty-queue checks before exiting |
| `IDLE_WAIT` | `15` | Seconds between idle checks |
| `MIN_CONFIDENCE` | `0.20` | Classification confidence floor |

---

## Output

### Per-page (live in logs)

```
======================================================================
  [3] http://example.onion/page
      depth=1  |  category=Directory  |  score=0.29  |     safe
      +2 new links queued
======================================================================
```

### Final summary (logs + `sentinel/data/report.txt`)

```
================================================================================
                   C R A W L   S U M M A R Y
================================================================================

  OVERVIEW
  | Total sites scanned................    11 |
  | Threats found......................     0 |

  CATEGORIES
  | Search Engine...................... ██████████████████████████████ 7
  | Directory.......................... █████████████████ 4

  LINK MAP  (page -> discovered URLs)
  ┌─ [Search Engine] http://example.onion
  │   Found 5 link(s):
  │   ├── ✔ http://example.onion/about  (Search Engine, 0.40)
  │   └── ✔ http://example.onion/add  (Directory, 0.29)

================================================================================
```

### Database

Results are stored in `sentinel/data/crawler.db` (SQLite) with three tables:
- **`queue`** — URL queue with status, depth, retry count, discovered-from
- **`sites`** — scan results with category, score, threat flag, timestamp
- **`link_graph`** — source→target link relationships

---

## Anti-Dead-State Design

| Scenario | Protection |
|----------|------------|
| Same URL keeps failing | Per-URL retry cap (`MAX_RETRIES=2`), then permanently skipped |
| Network/Tor goes down | Consecutive failure breaker (`MAX_CONSEC_FAIL=10`) aborts crawl |
| Queue empties | Idle retries with backoff, then clean exit |
| Browser crashes | Auto-restart + retry cap prevents loop |
| Page hangs | 60s page load timeout + 20s element wait |
| Graceful shutdown | SIGTERM/SIGINT → prints summary → saves report → exits |

---

## Rerun from Scratch

```bash
docker compose down -v
rm -f sentinel/data/crawler.db   # or: Remove-Item .\sentinel\data\crawler.db
docker compose up --build -d
docker logs -f sentinel-ai
```

> Omit `-v` to keep cached AI models and skip the ~100 MB re-download.

---

## Project Structure

```
DarkAI/
├── docker-compose.yml        # Service orchestration + config
├── LICENSE                   # MIT License
├── README.md                 # This file
├── MANUAL.md                 # Detailed run manual
├── .gitignore
├── data/
│   └── .gitkeep
└── sentinel/
    ├── Dockerfile            # Python 3.10 + Chromium + AI deps
    ├── main.py               # Crawler + AI classification engine
    ├── requirements.txt      # Pinned Python dependencies
    ├── .dockerignore
    └── data/                 # Runtime output (gitignored)
        ├── crawler.db        # SQLite database
        ├── report.txt        # Crawl summary report
        └── page_*.png        # Screenshots
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Crawler | Selenium + headless Chromium |
| Anonymity | Tor SOCKS5 proxy |
| OCR | EasyOCR |
| NLP | HuggingFace DistilBART (zero-shot classification) |
| Database | SQLite (WAL mode) |
| Container | Docker Compose |
| Language | Python 3.10 |

---

## Disclaimer

This tool is intended for **ethical cybersecurity research and academic purposes only**. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse.

---

## License

[MIT](LICENSE) — Ansh Verma
