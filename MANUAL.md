# DarkAI — Run Manual

> Complete guide to running the DarkAI Dark Web Intelligence Platform.

## Prerequisites

- **Docker Desktop** installed and running
- A terminal (PowerShell, CMD, Bash, etc.)
- ~4 GB RAM available for the sentinel-ai container

---

## Quick Start

```bash
cd DarkAI
docker compose up --build -d
```

Watch the crawl:

```bash
docker logs -f sentinel-ai
```

Open the dashboard: **http://localhost:5000**

Press `Ctrl+C` to stop following logs (crawler + dashboard keep running).

---

## Web Dashboard

Once the crawler starts, a live web dashboard is available at **http://localhost:5000**.

| Page | What it shows |
|------|---------------|
| **Overview** | Live stats, category charts, scan timeline |
| **Sites** | All scanned pages (click any row for details) |
| **Threats** | Threat sites with confidence scores |
| **Data Leaks** | Detected emails, cards, wallets, hashes |
| **Keywords** | Watchlist management + hit results |
| **Link Graph** | Interactive network visualization |
| **Search** | Full-text search across all data |
| **Alerts** | Alert channel status + history |

### Dashboard Features

- **Auto-refresh** — status updates every 5s, full data every 30s
- **Site detail modal** — click any site for screenshot, links, leaks, keywords
- **URL submission** — add `.onion` URLs to the scan queue from the dashboard
- **Export** — download JSON or CSV of all crawled data

---

## Change Seed URL

Edit `docker-compose.yml`:

```yaml
SEED_URL: "http://your-onion-address.onion"
```

Then rebuild: `docker compose up --build -d`

---

## Rerun from Scratch

```bash
docker compose down -v
rm -f sentinel/data/crawler.db
docker compose up --build -d
docker logs -f sentinel-ai
```

> **PowerShell:** use `Remove-Item .\sentinel\data\crawler.db` instead of `rm -f`.

> **Tip:** Omit `-v` to keep cached AI models (~100 MB).

---

## Configuration

Edit `docker-compose.yml` → `environment:` section.

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SEED_URL` | *(pre-configured)* | Starting URL |
| `MAX_DEPTH` | `0` | Link-hop depth limit (`0` = unlimited) |
| `MAX_SITES` | `0` | Max pages to scan (`0` = unlimited) |
| `CRAWL_DELAY` | `5` | Seconds between requests |
| `MAX_RETRIES` | `2` | Per-URL retry cap |
| `MAX_CONSEC_FAIL` | `10` | Consecutive failures before abort |

### Feature Toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_LEAK_DETECTION` | `true` | Scan for data leaks (emails, cards, wallets) |
| `ENABLE_KEYWORD_MONITOR` | `true` | Monitor for watchlist keywords |
| `ENABLE_CHANGE_DETECTION` | `true` | Detect content changes between scans |
| `ENABLE_FINGERPRINT_ROTATION` | `true` | Rotate user-agents + random delays |
| `ENABLE_API` | `true` | Run web dashboard on port 5000 |
| `API_PORT` | `5000` | Dashboard port |

### Alert Channels (Optional)

Uncomment and fill in `docker-compose.yml` to enable alerts:

```yaml
# Discord
DISCORD_WEBHOOK: "https://discord.com/api/webhooks/YOUR/WEBHOOK"

# Slack
SLACK_WEBHOOK: "https://hooks.slack.com/services/YOUR/WEBHOOK"

# Email (SMTP)
SMTP_HOST: "smtp.gmail.com"
SMTP_PORT: "587"
SMTP_USER: "you@gmail.com"
SMTP_PASS: "your-app-password"
ALERT_EMAIL_TO: "alerts@example.com"
```

Alerts fire automatically when the crawler detects threats, data leaks, keyword matches, or content changes.

---

## Keyword Monitoring

Add keywords to monitor via the dashboard (Keywords page) or the API:

```bash
# Add a keyword
curl -X POST http://localhost:5000/api/keywords \
  -H "Content-Type: application/json" \
  -d '{"keyword": "ransomware"}'

# View hits
curl http://localhost:5000/api/keyword-hits
```

---

## API Usage

All endpoints are documented in README.md. Quick examples:

```bash
# Crawler status
curl http://localhost:5000/api/status

# All scanned sites
curl http://localhost:5000/api/sites

# Threats only
curl http://localhost:5000/api/threats

# Search
curl "http://localhost:5000/api/search?q=bitcoin"

# Submit a URL to scan
curl -X POST http://localhost:5000/api/scan/submit \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.onion"}'

# Export all data
curl -o export.json http://localhost:5000/api/export/json
curl -o export.csv  http://localhost:5000/api/export/csv
```

---

## Useful Commands

| What | Command |
|------|---------|
| Follow logs live | `docker logs -f sentinel-ai` |
| Last 50 lines | `docker logs sentinel-ai --tail 50` |
| Container status | `docker ps -a` |
| Stop everything | `docker compose down` |
| Stop + wipe volumes | `docker compose down -v` |
| Open dashboard | `http://localhost:5000` |
| Check health | `curl http://localhost:5000/api/status` |

---

## Output

- **Dashboard**: `http://localhost:5000` (live web interface)
- **Logs**: per-page results + detailed summary with link map
- **Report**: `sentinel/data/report.txt` (auto-saved after crawl)
- **Database**: `sentinel/data/crawler.db` (SQLite, 9 tables)
- **Screenshots**: `sentinel/data/page_*.png`
- **Export**: JSON/CSV via dashboard or API

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Container exits immediately | Check `SEED_URL` is set in `docker-compose.yml` |
| `Cannot connect to Docker daemon` | Start Docker Desktop |
| `Tor connection refused` | Restart: `docker compose restart sentinel-ai` |
| Seed "already in queue" | Delete DB first (see Rerun section) |
| Out of memory | Lower `MAX_SITES` or increase Docker memory limit |
| Dashboard not loading | Check `ENABLE_API` is `true` and port 5000 is free |
| No alerts received | Verify webhook URLs / SMTP credentials in env vars |
| Dashboard shows no data | Wait for crawler to scan at least one page |
