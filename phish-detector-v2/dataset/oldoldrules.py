#!/usr/bin/env python3
"""
oldoldrules.py — simple rule engine for phishing detection.

Exports:
  - classify_email(sender, subject, body) -> (label_str, total_score)
  - load_config_to_rules()  # load config.json into the sets
  - Globals used by app.py settings UI:
      WHITELIST, SUSPICIOUS_KEYWORDS, KNOWN_BRANDS
"""

import os
import re
import ipaddress
from urllib.parse import urlparse
from typing import Iterable

# ====== Config (single source of truth) ======

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

DEFAULT_CONFIG = {
    "whitelist": [
        "ntu.edu.sg",
        "example.com",
    ],
    "keywords": [
        "urgent", "verify", "account", "password", "click",
        "confirm", "login", "reset", "update", "invoice", "refund", "otp",
        "suspend", "limitation", "billing", "payment", "secure", "action required"
    ],
    "brands": [
        "paypal.com", "google.com", "microsoft.com"
    ],
}

# Mutable sets used by the rules (app edits these and writes back to config.json)
WHITELIST = set(DEFAULT_CONFIG["whitelist"])
SUSPICIOUS_KEYWORDS = set(DEFAULT_CONFIG["keywords"])
KNOWN_BRANDS = set(DEFAULT_CONFIG["brands"])  # aka "legit domains" for lookalike checks


def load_config_to_rules() -> None:
    """Load config.json into the in-memory sets. Falls back to DEFAULT_CONFIG."""
    import json
    cfg = None
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = None

    if not isinstance(cfg, dict):
        cfg = DEFAULT_CONFIG

    WHITELIST.clear()
    WHITELIST.update({d.strip().lower() for d in cfg.get("whitelist", []) if d.strip()})

    SUSPICIOUS_KEYWORDS.clear()
    SUSPICIOUS_KEYWORDS.update({k.strip().lower() for k in cfg.get("keywords", []) if k.strip()})

    KNOWN_BRANDS.clear()
    KNOWN_BRANDS.update({b.strip().lower() for b in cfg.get("brands", []) if b.strip()})


# Load config once at import (evaluate.py also calls this explicitly to be safe)
load_config_to_rules()


# ====== Small utilities (kept here so you don't need utils.py) ======

def levenshtein_distance(a: str, b: str) -> int:
    """Classic Levenshtein distance (edit distance)."""
    a, b = a.lower(), b.lower()
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = prev[j] + 1
            dele = cur[j - 1] + 1
            rep = prev[j - 1] + (ca != cb)
            cur.append(min(ins, dele, rep))
        prev = cur
    return prev[-1]


URL_REGEX = re.compile(r'http[s]?://[^\s<>()"]+', re.IGNORECASE)

def extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text or "")

def url_domain(url: str) -> str:
    """Return hostname (lower, strip port & creds) from a URL string."""
    try:
        p = urlparse(url)
        host = (p.netloc or "").lower()
        # remove userinfo if present
        if "@" in host:
            host = host.split("@", 1)[-1]
        # strip port
        if ":" in host:
            host = host.split(":", 1)[0]
        return host
    except Exception:
        return ""

def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def domain_matches(host: str, ref_domain: str) -> bool:
    """True if host is ref_domain or a subdomain of it."""
    host = (host or "").lower()
    ref = (ref_domain or "").lower()
    return host == ref or host.endswith("." + ref)


# ====== Rule weights / constants ======

THRESHOLD = 10  # final decision boundary

# Common URL shorteners often used in phishing
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "lnkd.in"
}

# Popular freemail providers (often used by attackers)
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "msn.com", "live.com", "icloud.com", "proton.me", "protonmail.com"
}


# ====== Individual rules (each returns a partial score) ======

def whitelist_check(sender_email: str) -> int:
    """
    If sender domain is not in whitelist, add suspicion.
    +2 if not whitelisted; 0 if whitelisted
    """
    domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    return 0 if domain in WHITELIST else 2


def keyword_check(subject: str, body: str) -> int:
    """
    Suspicious keywords:
      +3 for each keyword found in Subject
      +1 for each keyword found in Body
      +2 extra if keyword appears in the first 200 chars of the body (early pressure)
    (keywords are checked as lowercase substrings; unique keywords counted once per location)
    """
    s = (subject or "").lower()
    b = (body or "").lower()
    early = b[:200]

    score = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in s:
            score += 3
        found_body = kw in b
        if found_body:
            score += 1
        if kw in early:
            score += 2
    return score


def edit_distance_check(sender_email: str) -> int:
    """
    Lookalike domain check against known brands:
      Compare the second-level part (before TLD), e.g., 'paypa1' vs 'paypal'
      +5 if distance <= 1
    """
    dom = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    if not dom:
        return 0

    def sld(d: str) -> str:
        parts = d.split(".")
        return parts[-2] if len(parts) >= 2 else parts[0]

    sld_sender = sld(dom)
    score = 0
    for brand in KNOWN_BRANDS:
        if not brand:
            continue
        if domain_matches(dom, brand):
            continue  # it's the legit brand domain
        if levenshtein_distance(sld_sender, sld(brand)) <= 1:
            score += 5
            break
    return score


def suspicious_url_check(subject: str, body: str) -> int:
    """
    Suspicious link detection:
      +6 for IP-literal links
      +4 for URLs containing user@host
      +4 for known shorteners (bit.ly, t.co, ...)
      +5 if text mentions a legit brand domain but the link goes elsewhere
      +2 if a suspicious keyword appears within ±100 chars of a link
    """
    score = 0
    text_lower = f"{subject or ''}\n{body or ''}".lower()

    # any claimed legit domain in the text
    claimed = [d for d in KNOWN_BRANDS if d in text_lower]

    for m in re.finditer(r"http[s]?://\S+", text_lower):
        url = m.group(0)
        host = url_domain(url)

        # IP literal
        if is_ip_literal(host):
            score += 6

        # user@host
        if "@" in (url.split("://", 1)[-1].split("/", 1)[0]):
            score += 4

        # shortener
        if host in SHORTENER_DOMAINS:
            score += 4

        # claimed-domain mismatch (brand mentioned, but link goes elsewhere)
        for d in claimed:
            if not domain_matches(host, d):
                score += 5
                break

        # keyword within ±100 chars of the URL
        left = max(0, m.start() - 100)
        right = min(len(text_lower), m.end() + 100)
        window = text_lower[left:right]
        if any(kw in window for kw in SUSPICIOUS_KEYWORDS):
            score += 2

    return score


def basic_link_penalties(sender_email: str, body: str) -> int:
    """
    Base penalties for emails that contain links but otherwise look 'normal':
      +4 if any URL present AND sender not whitelisted
      +2 if 2 or more URLs
      +2 if sender domain is a freemail provider AND there is a URL
    This catches many phish that previously scored only +2 from whitelist_check.
    """
    urls = extract_urls(body)
    if not urls:
        return 0

    dom = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    score = 0
    if dom not in WHITELIST:
        score += 4
    if len(urls) >= 2:
        score += 2
    if dom in FREE_EMAIL_DOMAINS:
        score += 2
    return score


# ====== Final classifier ======

def classify_email(sender: str, subject: str, body: str):
    """
    Combine all partial scores into a final decision.

    Current recipe:
      - whitelist_check
      - keyword_check
      - edit_distance_check
      - suspicious_url_check
      - basic_link_penalties   (NEW to catch 'boring link' phish)

      label = "Phishing" if score >= THRESHOLD else "Safe"
    """
    score = 0
    score += whitelist_check(sender)
    score += keyword_check(subject, body)
    score += edit_distance_check(sender)
    score += suspicious_url_check(subject, body)
    score += basic_link_penalties(sender, body)

    label = "Phishing" if score >= THRESHOLD else "Safe"
    return label, score
