# DarkAI — Dark Web Intelligence Platform

> **AI-powered dark web crawler with real-time threat detection, data leak scanning, keyword monitoring, link graph mapping, and a live web dashboard.**

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)
![Tor](https://img.shields.io/badge/Network-Tor-7D4698)

---

## What Makes DarkAI Unique

No open-source tool combines **all** of these in one package:

| Feature | DarkAI | Others |
|---------|--------|--------|
| AI content classification (zero-shot NLP) | ✅ | ❌ |
| Automated data leak detection (emails, cards, crypto) | ✅ | ❌ |
| Real-time web dashboard with charts | ✅ | ❌ |
| Interactive link graph visualization | ✅ | ❌ |
| Keyword monitoring with alerts | ✅ | ❌ |
| Discord / Slack / Email alerts | ✅ | Partial |
| Site change detection | ✅ | ❌ |
| Fingerprint avoidance (UA rotation, random delays) | ✅ | ❌ |
| Anti-dead-state algorithm | ✅ | ❌ |
| Full REST API with JSON/CSV export | ✅ | ❌ |
| Screenshot evidence archive | ✅ | Partial |
| One-command Docker deployment | ✅ | ✅ |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      DOCKER COMPOSE                          │
│                                                              │
│  ┌──────────────┐     SOCKS5      ┌───────────────────────┐ │
│  │  Tor Service  │◄──────────────►│     Sentinel-AI        │ │
│  │  (port 9050)  │                │                        │ │
│  └──────────────┘                │  ┌──────────────────┐  │ │
│                                   │  │  Crawl Engine     │  │ │
│                                   │  │  Selenium+Chrome  │  │ │
│                                   │  └────────┬─────────┘  │ │
│                                   │           │             │ │
│                                   │  ┌────────▼─────────┐  │ │
│                                   │  │  AI Pipeline      │  │ │
│                                   │  │  EasyOCR → NLP    │  │ │
│                                   │  │  DistilBART       │  │ │
│                                   │  └────────┬─────────┘  │ │
│                                   │           │             │ │
│                                   │  ┌────────▼─────────┐  │ │
│                                   │  │  Feature Engines  │  │ │
│                                   │  │  • Leak Detector  │  │ │
│                                   │  │  • Keyword Monitor│  │ │
│                                   │  │  • Change Detect  │  │ │
│                                   │  │  • Alert System   │  │ │
│                                   │  └────────┬─────────┘  │ │
│                                   │           │             │ │
│  ┌────────────────┐              │  ┌────────▼─────────┐  │ │
│  │  Web Dashboard  │◄────────────│  │  SQLite + API     │  │ │
│  │  localhost:5000 │  Flask API   │  │  (9 tables)       │  │ │
│  └────────────────┘              │  └──────────────────┘  │ │
│                                   └───────────────────────┘ │
│  ┌────────────────┐                                         │
│  │  Alert Channels │  Discord / Slack / Email                │
│  └────────────────┘                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

### 🕵️ Intelligent Crawling
- **Chain crawling** — follows cross-domain `.onion` links automatically
- **Unlimited mode** — `MAX_DEPTH=0` and `MAX_SITES=0` for continuous crawling
- **Anti-dead-state** — per-URL retry cap, consecutive failure breaker, idle detection
- **Fingerprint avoidance** — rotates user-agents, randomized delays, WebRTC disabled

### 🧠 AI Classification
- **Zero-shot NLP** — DistilBART classifies pages into 18 categories without training
- **Threat categories** — Cryptocurrency Scam, Drug Market, Hacking Service, Phishing, Weapons Market, Human Trafficking, Counterfeit Documents, Ransomware, Stolen Data Market, Malware Distribution
- **Safe categories** — Safe Blog, Directory, Search Engine, News Site, Privacy Tool, Forum, Email Service, Whistleblower Platform
- **OCR extraction** — EasyOCR reads text from page screenshots

### 🔓 Data Leak Detection
- Emails, credit cards (Visa/MC/Amex/Discover with Luhn validation)
- Cryptocurrency wallets (BTC, ETH, XMR)
- Phone numbers, Social Security Numbers
- Password hashes (MD5, SHA-1, SHA-256, bcrypt)
- IPv4 addresses, API keys/tokens

### 🔍 Keyword Monitoring
- Add keywords via dashboard or API
- Real-time scanning with context snippets
- Alerts on match with surrounding text

### 🕸️ Link Graph
- Interactive network visualization (vis.js)
- Directed graph showing crawl paths
- Color-coded: green=safe, red=threat, gray=unscanned
- Incoming/outgoing link analysis per site

### 📊 Web Dashboard
- **Real-time overview** — live stats, category charts, scan timeline
- **Threat intelligence** — threat grid with confidence scores
- **Data leak browser** — filterable leak table with type badges
- **Full-text search** — search across URLs, page content, and leaks
- **Site detail modal** — screenshot, links, leaks, keywords per page
- **Export** — JSON and CSV download
- **URL submission** — add scan targets via the dashboard

### 🔔 Alert System
- **Discord** — rich embeds with color-coded threat levels
- **Slack** — formatted blocks with context
- **Email** — HTML-styled alerts via SMTP
- Rate limiting to prevent spam
- Alert types: threat, leak, keyword match, content change

### 📈 Analytics
- Category distribution (doughnut chart)
- Scan timeline (line chart)
- Threat timeline (bar chart)
- Leak type breakdown (polar area chart)
- Top linked pages ranking
- Scan session history

---

## Quick Start

```bash
# One command to start everything
docker compose up --build -d

# Open the dashboard
# http://localhost:5000

# View crawler logs
docker compose logs -f sentinel-ai

# Stop
docker compose down
```

---

## Configuration

All settings via environment variables in `docker-compose.yml`:

### Core Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `SEED_URL` | *(The Onion Hub)* | Starting URL to crawl |
| `MAX_DEPTH` | `0` | Max link depth (0 = unlimited) |
| `MAX_SITES` | `0` | Max sites to scan (0 = unlimited) |
| `CRAWL_DELAY` | `5` | Seconds between requests |
| `MIN_CONFIDENCE` | `0.20` | AI classification threshold |
| `MAX_RETRIES` | `2` | Per-URL retry cap |
| `MAX_CONSEC_FAIL` | `10` | Abort after N consecutive failures |

### Feature Toggles
| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_LEAK_DETECTION` | `true` | Scan pages for data leaks |
| `ENABLE_KEYWORD_MONITOR` | `true` | Monitor pages for keywords |
| `ENABLE_CHANGE_DETECTION` | `true` | Detect content changes |
| `ENABLE_FINGERPRINT_ROTATION` | `true` | Rotate user-agents |
| `ENABLE_API` | `true` | Run web dashboard |
| `API_PORT` | `5000` | Dashboard port |

### Alert Channels (Optional)
| Variable | Description |
|----------|-------------|
| `DISCORD_WEBHOOK` | Discord webhook URL |
| `SLACK_WEBHOOK` | Slack incoming webhook URL |
| `SMTP_HOST` | SMTP server (e.g., smtp.gmail.com) |
| `SMTP_PORT` | SMTP port (default: 587) |
| `SMTP_USER` | SMTP username |
| `SMTP_PASS` | SMTP password / app password |
| `ALERT_EMAIL_TO` | Recipient email address |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Crawler status + live stats |
| GET | `/api/sites` | All scanned sites (filterable) |
| GET | `/api/sites/<url>` | Site detail + leaks + links |
| GET | `/api/threats` | Threat sites only |
| GET | `/api/leaks` | All detected data leaks |
| GET | `/api/keywords` | Keyword watchlist |
| POST | `/api/keywords` | Add keyword `{"keyword": "..."}` |
| DELETE | `/api/keywords/<id>` | Remove keyword |
| GET | `/api/keyword-hits` | Keyword match results |
| GET | `/api/link-graph` | Graph data (nodes + edges) |
| GET | `/api/stats` | Charts + analytics data |
| GET | `/api/search?q=` | Full-text search |
| POST | `/api/scan/submit` | Submit URL `{"url": "..."}` |
| GET | `/api/export/json` | Download full data as JSON |
| GET | `/api/export/csv` | Download sites as CSV |
| GET | `/api/screenshot/<hash>` | Page screenshot image |
| GET | `/api/sessions` | Scan session history |
| GET | `/api/alerts/config` | Alert channel status |
| GET | `/api/alerts/history` | Alert log |

---

## Project Structure

```
DarkAI/
├── docker-compose.yml          # Orchestration (Tor + Sentinel)
├── README.md                   # Documentation
├── MANUAL.md                   # Run manual
├── LICENSE                     # MIT License
├── .gitignore
├── data/                       # Runtime data (gitignored)
│   └── .gitkeep
└── sentinel/
    ├── Dockerfile              # Python 3.10 + Chromium + AI
    ├── main.py                 # Crawler engine (all features)
    ├── api.py                  # Flask REST API + dashboard
    ├── leak_detector.py        # Data leak regex engine
    ├── alerts.py               # Multi-channel alert system
    ├── requirements.txt        # Pinned dependencies
    ├── .dockerignore
    ├── data/                   # Mounted data volume
    │   └── .gitkeep
    ├── templates/
    │   └── index.html          # Dashboard SPA
    └── static/
        ├── css/
        │   └── style.css       # Dark theme styles
        └── js/
            └── app.js          # Dashboard logic
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Crawler | Selenium + headless Chromium |
| Network | Tor SOCKS5 proxy |
| OCR | EasyOCR |
| NLP | HuggingFace DistilBART (zero-shot) |
| Leak Detection | Custom regex engine (Luhn validation) |
| Database | SQLite WAL (9 tables) |
| API | Flask |
| Dashboard | Vanilla JS + Chart.js + vis.js |
| Alerts | Discord/Slack webhooks + SMTP |
| Container | Docker Compose |

---

## Anti-Dead-State Design

| Mechanism | What it prevents |
|-----------|-----------------|
| Per-URL retry cap (`MAX_RETRIES=2`) | Infinite retry loops on broken pages |
| Consecutive failure breaker (`MAX_CONSEC_FAIL=10`) | Stuck crawling when Tor/network dies |
| Idle detection (`IDLE_RETRIES=3`) | Spinning forever on empty queue |
| Page timeout (60s) | Hanging on slow/dead pages |
| Browser crash recovery | Automatic restart on Selenium crash |
| Fingerprint rotation | Detection avoidance |
| Randomized delays | Traffic pattern obfuscation |

---

## Disclaimer

This tool is for **authorized security research and educational purposes only**. Accessing dark web content may violate laws in your jurisdiction. The authors are not responsible for misuse. Always obtain proper authorization before scanning any network or website.

---

## License

MIT License — see [LICENSE](LICENSE)

---

**Created by Ansh Verma**
