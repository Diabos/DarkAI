# DarkAI — Run Manual

> Step-by-step guide to run the project on your own machine.

## Prerequisites

- **Docker Desktop** installed and running
- A terminal (PowerShell, CMD, Bash, etc.)

---

## Run (1 command)

```bash
cd DarkAI
docker compose up --build -d
```

Watch the crawl:

```bash
docker logs -f sentinel-ai
```

Press `Ctrl+C` to stop following logs (crawler keeps running).

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

Edit `docker-compose.yml` → `environment:` section:

| Variable | Default | Description |
|----------|---------|-------------|
| `SEED_URL` | *(pre-configured)* | Starting URL |
| `MAX_DEPTH` | `0` | Link-hop depth limit (`0` = unlimited) |
| `MAX_SITES` | `0` | Max pages to scan (`0` = unlimited) |
| `CRAWL_DELAY` | `5` | Seconds between requests |
| `MAX_RETRIES` | `2` | Per-URL retry cap |
| `MAX_CONSEC_FAIL` | `10` | Consecutive failures before abort |

---

## Useful Commands

| What | Command |
|------|---------|
| Follow logs live | `docker logs -f sentinel-ai` |
| Last 50 lines | `docker logs sentinel-ai --tail 50` |
| Container status | `docker ps -a` |
| Stop everything | `docker compose down` |
| Stop + wipe volumes | `docker compose down -v` |

---

## Output

- **Logs**: per-page results + final summary with link map
- **Report**: `sentinel/data/report.txt` (auto-saved)
- **Database**: `sentinel/data/crawler.db` (SQLite)
- **Screenshots**: `sentinel/data/page_*.png`

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Container exits immediately | Check `SEED_URL` is set in `docker-compose.yml` |
| `Cannot connect to Docker daemon` | Start Docker Desktop |
| `Tor connection refused` | Restart: `docker compose restart sentinel-ai` |
| Seed "already in queue" | Delete DB first (see Rerun section) |
| Out of memory | Lower `MAX_SITES` or increase Docker memory limit |
