"""
DarkAI — Data Leak Detection Engine
====================================
Scans page text for sensitive data patterns:
  • Email addresses
  • Credit / debit card numbers (Visa, MC, Amex, Discover)
  • Cryptocurrency wallet addresses (BTC, ETH, XMR)
  • Phone numbers (international formats)
  • Social Security Numbers (US)
  • Password hashes (MD5, SHA-1, SHA-256, bcrypt)
  • API keys / tokens (generic long hex/base64)
  • IP addresses (IPv4)

Each detector returns a list of (leak_type, matched_value) tuples.
"""

import re
from typing import List, Tuple

# ──────────────────────────────────────────────
# Regex patterns — compiled once at import time
# ──────────────────────────────────────────────

# Email
_RE_EMAIL = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
)

# Credit cards  (Visa, MC, Amex, Discover — with optional separators)
_RE_CREDIT_CARD = re.compile(
    r"\b(?:"
    r"4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # Visa
    r"|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # MC
    r"|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}"  # Amex
    r"|6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # Discover
    r")\b"
)

# Bitcoin (P2PKH, P2SH, Bech32)
_RE_BTC = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b")

# Ethereum
_RE_ETH = re.compile(r"\b0x[0-9a-fA-F]{40}\b")

# Monero
_RE_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Phone (international)
_RE_PHONE = re.compile(
    r"(?:\+?1[\s\-\.]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}"
)

# US Social Security Number
_RE_SSN = re.compile(r"\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b")

# Password hashes
_RE_MD5    = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1   = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_BCRYPT = re.compile(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}")

# Generic API key / token  (long hex or base64  strings ≥ 32 chars)
_RE_API_KEY = re.compile(r"\b[A-Za-z0-9+/=_\-]{32,128}\b")

# IPv4
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# ──────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────

# Minimum text length to bother scanning
_MIN_TEXT = 10

# Words that are common in normal pages and cause false-positive API-key matches
_API_KEY_BLOCKLIST = {
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789abcdef",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "undefined",
}


def _dedup(matches: list) -> list:
    """Remove duplicates while preserving order."""
    seen = set()
    out = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def scan_text(text: str) -> List[Tuple[str, str]]:
    """
    Scan *text* for data leak patterns.

    Returns a list of ``(leak_type, value)`` tuples, e.g.::

        [("email", "admin@example.com"),
         ("credit_card", "4111111111111111"),
         ("btc_wallet", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")]
    """
    if not text or len(text) < _MIN_TEXT:
        return []

    results: List[Tuple[str, str]] = []

    # Email
    for m in _RE_EMAIL.findall(text):
        results.append(("email", m))

    # Credit cards
    for m in _RE_CREDIT_CARD.findall(text):
        clean = m.replace(" ", "").replace("-", "")
        if _luhn_check(clean):
            results.append(("credit_card", clean))

    # Crypto wallets
    for m in _RE_BTC.findall(text):
        results.append(("btc_wallet", m))
    for m in _RE_ETH.findall(text):
        results.append(("eth_wallet", m))
    for m in _RE_XMR.findall(text):
        results.append(("xmr_wallet", m))

    # Phone numbers
    for m in _RE_PHONE.findall(text):
        digits = re.sub(r"\D", "", m)
        if 10 <= len(digits) <= 15:
            results.append(("phone", m.strip()))

    # SSN
    for m in _RE_SSN.findall(text):
        results.append(("ssn", m))

    # Password hashes  (order matters: SHA-256 > SHA-1 > MD5 to avoid subset matches)
    seen_hashes = set()
    for m in _RE_SHA256.findall(text):
        seen_hashes.add(m)
        results.append(("sha256_hash", m))
    for m in _RE_SHA1.findall(text):
        if m not in seen_hashes:
            seen_hashes.add(m)
            results.append(("sha1_hash", m))
    for m in _RE_MD5.findall(text):
        if m not in seen_hashes:
            results.append(("md5_hash", m))
    for m in _RE_BCRYPT.findall(text):
        results.append(("bcrypt_hash", m))

    # IPv4
    for m in _RE_IPV4.findall(text):
        # Filter out common non-interesting IPs
        if m not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            results.append(("ipv4", m))

    return _dedup(results)


def _luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    try:
        digits = [int(d) for d in number]
    except ValueError:
        return False
    if len(digits) < 13:
        return False
    checksum = 0
    odd = True
    for d in reversed(digits):
        if not odd:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        odd = not odd
    return checksum % 10 == 0


def get_leak_summary(leaks: List[Tuple[str, str]]) -> dict:
    """Group leaks by type and return a summary dict."""
    summary: dict = {}
    for leak_type, value in leaks:
        summary.setdefault(leak_type, []).append(value)
    return summary


# ──────────────────────────────────────────────
#  Keyword monitoring
# ──────────────────────────────────────────────

def scan_keywords(text: str, keywords: List[str], context_chars: int = 80) -> List[Tuple[str, str]]:
    """
    Search *text* for each keyword (case-insensitive).

    Returns ``(keyword, context_snippet)`` for every match.
    """
    if not text or not keywords:
        return []

    text_lower = text.lower()
    results = []

    for kw in keywords:
        kw_lower = kw.lower()
        start = 0
        while True:
            idx = text_lower.find(kw_lower, start)
            if idx == -1:
                break
            # Extract surrounding context
            ctx_start = max(0, idx - context_chars)
            ctx_end = min(len(text), idx + len(kw) + context_chars)
            snippet = text[ctx_start:ctx_end].replace("\n", " ").strip()
            if ctx_start > 0:
                snippet = "..." + snippet
            if ctx_end < len(text):
                snippet = snippet + "..."
            results.append((kw, snippet))
            start = idx + len(kw)

    return results
