"""
DarkAI — Multi-Channel Alert System
=====================================
Sends real-time alerts when the crawler detects:
  • Threat sites (hacking, drugs, scams, phishing)
  • Data leaks (emails, credit cards, crypto wallets, etc.)
  • Keyword matches (user-defined watchlist)
  • Site content changes (hash mismatch)

Supported channels:
  - Discord (webhook URL)
  - Slack  (webhook URL)
  - Email  (SMTP)
"""

import os
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError

log = logging.getLogger("sentinel.alerts")

# ──────────────────────────────────────────────
#  Configuration (all via environment variables)
# ──────────────────────────────────────────────

DISCORD_WEBHOOK  = os.getenv("DISCORD_WEBHOOK", "").strip()
SLACK_WEBHOOK    = os.getenv("SLACK_WEBHOOK", "").strip()
SMTP_HOST        = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT        = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER        = os.getenv("SMTP_USER", "").strip()
SMTP_PASS        = os.getenv("SMTP_PASS", "").strip()
ALERT_EMAIL_TO   = os.getenv("ALERT_EMAIL_TO", "").strip()
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", SMTP_USER).strip()

# Rate limiting: minimum seconds between identical alert messages
ALERT_COOLDOWN   = int(os.getenv("ALERT_COOLDOWN", "60"))
_recent_alerts: dict = {}  # message_hash -> timestamp


def _is_rate_limited(msg_key: str) -> bool:
    """Prevent spamming the same alert repeatedly."""
    now = datetime.utcnow().timestamp()
    last = _recent_alerts.get(msg_key, 0)
    if now - last < ALERT_COOLDOWN:
        return True
    _recent_alerts[msg_key] = now
    return False


# ──────────────────────────────────────────────
#  Discord
# ──────────────────────────────────────────────

def _send_discord(title: str, message: str, color: int = 0xFF0000):
    """Send a rich embed to a Discord webhook."""
    if not DISCORD_WEBHOOK:
        return False
    payload = {
        "embeds": [{
            "title": title,
            "description": message[:4096],
            "color": color,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "footer": {"text": "DarkAI Alert System"},
        }]
    }
    try:
        req = Request(
            DISCORD_WEBHOOK,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req, timeout=10)
        log.info(f"Discord alert sent: {title}")
        return True
    except URLError as e:
        log.warning(f"Discord alert failed: {e}")
        return False


# ──────────────────────────────────────────────
#  Slack
# ──────────────────────────────────────────────

def _send_slack(title: str, message: str):
    """Send a message to a Slack incoming webhook."""
    if not SLACK_WEBHOOK:
        return False
    payload = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": message[:3000]}},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"_DarkAI Alert | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_"}
            ]}
        ]
    }
    try:
        req = Request(
            SLACK_WEBHOOK,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req, timeout=10)
        log.info(f"Slack alert sent: {title}")
        return True
    except URLError as e:
        log.warning(f"Slack alert failed: {e}")
        return False


# ──────────────────────────────────────────────
#  Email (SMTP)
# ──────────────────────────────────────────────

def _send_email(subject: str, body: str):
    """Send an alert email via SMTP."""
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, ALERT_EMAIL_TO]):
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[DarkAI Alert] {subject}"
        msg["From"] = ALERT_EMAIL_FROM
        msg["To"] = ALERT_EMAIL_TO

        html = f"""
        <html><body style="font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px;">
            <h2 style="color: #ff4444;">{subject}</h2>
            <pre style="background: #16213e; padding: 15px; border-radius: 8px; color: #e0e0e0;">{body}</pre>
            <hr style="border-color: #333;">
            <p style="color: #666; font-size: 12px;">DarkAI Alert System | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
        </body></html>
        """
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(ALERT_EMAIL_FROM, [ALERT_EMAIL_TO], msg.as_string())

        log.info(f"Email alert sent: {subject}")
        return True
    except Exception as e:
        log.warning(f"Email alert failed: {e}")
        return False


# ──────────────────────────────────────────────
#  High-level alert functions
# ──────────────────────────────────────────────

def _broadcast(title: str, message: str, color: int = 0xFF0000):
    """Send an alert through ALL configured channels."""
    sent = []
    if DISCORD_WEBHOOK:
        if _send_discord(title, message, color):
            sent.append("discord")
    if SLACK_WEBHOOK:
        if _send_slack(title, message):
            sent.append("slack")
    if SMTP_HOST:
        if _send_email(title, message):
            sent.append("email")
    return sent


def alert_threat(url: str, category: str, score: float):
    """Alert: a threat site was detected."""
    msg_key = f"threat:{url}"
    if _is_rate_limited(msg_key):
        return []
    title = f"\u26a0 THREAT DETECTED: {category}"
    message = (
        f"**URL:** {url}\n"
        f"**Category:** {category}\n"
        f"**Confidence:** {score:.0%}\n"
        f"**Time:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    )
    return _broadcast(title, message, color=0xFF0000)


def alert_leak(url: str, leak_type: str, leak_count: int, samples: list):
    """Alert: data leaks found on a page."""
    msg_key = f"leak:{url}:{leak_type}"
    if _is_rate_limited(msg_key):
        return []
    title = f"\U0001f6a8 DATA LEAK: {leak_count} {leak_type}(s) found"
    sample_str = "\n".join(f"  \u2022 {s}" for s in samples[:5])
    message = (
        f"**URL:** {url}\n"
        f"**Type:** {leak_type}\n"
        f"**Count:** {leak_count}\n"
        f"**Samples:**\n{sample_str}"
    )
    return _broadcast(title, message, color=0xFF6600)


def alert_keyword(url: str, keyword: str, snippet: str):
    """Alert: a monitored keyword was found."""
    msg_key = f"kw:{url}:{keyword}"
    if _is_rate_limited(msg_key):
        return []
    title = f"\U0001f50d KEYWORD MATCH: \"{keyword}\""
    message = (
        f"**URL:** {url}\n"
        f"**Keyword:** {keyword}\n"
        f"**Context:** ...{snippet[:500]}..."
    )
    return _broadcast(title, message, color=0xFFCC00)


def alert_site_change(url: str, old_hash: str, new_hash: str):
    """Alert: a previously-scanned site changed its content."""
    msg_key = f"change:{url}"
    if _is_rate_limited(msg_key):
        return []
    title = "\U0001f504 SITE CONTENT CHANGED"
    message = (
        f"**URL:** {url}\n"
        f"**Old hash:** {old_hash[:16]}...\n"
        f"**New hash:** {new_hash[:16]}...\n"
        f"**Time:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    )
    return _broadcast(title, message, color=0x00CCFF)


def has_any_channel() -> bool:
    """Return True if at least one alert channel is configured."""
    return bool(DISCORD_WEBHOOK or SLACK_WEBHOOK or SMTP_HOST)
