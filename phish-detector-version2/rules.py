# rules.py
"""
Rule-based phishing detector (single-list design).
- One list: LEGIT_DOMAINS (used for whitelist + edit-distance lookalikes)
- Suspicious keywords with position scoring (subject heavier + early body bonus)
- Suspicious URL checks (IP literal, user@host, claimed-domain mismatch)
- Config stored in config.json; auto-created/migrated on first run
"""

import os, json, re
from urllib.parse import urlparse

# This is the default configuration if json file not exist
DEFAULT_CONFIG = {
    "legit_domains": ["singapore.tech.edu.sg"],
    "keywords": ["urgent", "verify", "account", "password", "click"],
}
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
# ===== Mutable sets used by rules =====
LEGIT_DOMAINS = set()
SUSPICIOUS_KEYWORDS = set()

# Backwards-compatibility: older UI imports SUS_KEYWORDS
SUS_KEYWORDS = SUSPICIOUS_KEYWORDS

# ---------- Config helpers (single source of truth) ----------

def _persist(path: str, cfg: dict) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def _apply_cfg(cfg: dict) -> None:
    """Copy cfg values into module-level sets (lowercased)."""
    LEGIT_DOMAINS.clear()
    LEGIT_DOMAINS.update({d.strip().lower() for d in cfg.get("legit_domains", []) if d.strip()})
    SUSPICIOUS_KEYWORDS.clear()
    SUSPICIOUS_KEYWORDS.update({k.strip().lower() for k in cfg.get("keywords", []) if k.strip()})

def load_config_to_rules(path: str = CONFIG_PATH) -> None:
    """
    Load config.json. If file is missing, create from defaults.
    If an old schema is found (whitelist/brands), migrate to legit_domains.
    """
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = DEFAULT_CONFIG.copy()
    else:
        cfg = DEFAULT_CONFIG.copy()
        _persist(path, cfg)

    # Migrate old schema → new (whitelist + brands → legit_domains)
    if "legit_domains" not in cfg:
        wl = cfg.get("whitelist", []) or []
        br = cfg.get("brands", []) or []
        cfg["legit_domains"] = sorted({*wl, *br})
        cfg.pop("whitelist", None)
        cfg.pop("brands", None)
        _persist(path, cfg)

    cfg.setdefault("legit_domains", [])
    cfg.setdefault("keywords", [])
    _apply_cfg(cfg)

def save_rules_to_config(path: str = CONFIG_PATH) -> None:
    """Persist current sets to config.json."""
    cfg = {
        "legit_domains": sorted(LEGIT_DOMAINS),
        "keywords": sorted(SUSPICIOUS_KEYWORDS),
    }
    _persist(path, cfg)

def reset_to_defaults(path: str = CONFIG_PATH) -> None:
    """Reset sets + config.json to DEFAULT_CONFIG."""
    _apply_cfg(DEFAULT_CONFIG)
    _persist(path, DEFAULT_CONFIG)

# Load config when module is imported
load_config_to_rules()

# ---------- Small helpers ----------

def levenshtein_distance(a: str, b: str) -> int:
    """Classic edit distance (insert/delete/substitute = 1)."""
    la, lb = len(a), len(b)
    dp = [[0]*(lb+1) for _ in range(la+1)]
    for i in range(la+1): dp[i][0] = i
    for j in range(lb+1): dp[0][j] = j
    for i in range(1, la+1):
        for j in range(1, lb+1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
    return dp[la][lb]

def extract_urls(text: str):
    """Return all http/https URLs in text."""
    return re.findall(r"http[s]?://\S+", text)

def url_domain(url: str) -> str:
    """
    Extract host from URL (strip credentials/ports).
    e.g., http://user:pass@host:8080/path -> host
    """
    try:
        netloc = urlparse(url).netloc
        if "@" in netloc:  # strip credentials
            netloc = netloc.split("@", 1)[-1]
        if ":" in netloc:  # strip port
            netloc = netloc.split(":", 1)[0]
        return netloc.lower()
    except Exception:
        return ""

def is_ip_literal(host: str) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host))

def domain_matches(host: str, root: str) -> bool:
    """True if host == root or host ends with .root (subdomain)."""
    host, root = host.lower(), root.lower()
    return host == root or host.endswith("." + root)

# ---------- Individual rules (scored) ----------

def whitelist_check(sender_email: str) -> int:
    """Small penalty if sender NOT in LEGIT_DOMAINS."""
    domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    return 0 if domain in LEGIT_DOMAINS else 2

def keyword_check(subject: str, body: str) -> int:
    """
    Suspicious keyword scoring:
      - +3 for each keyword in SUBJECT (higher weight)
      - +1 for each keyword anywhere in BODY
      - +2 EXTRA if keyword appears EARLY in BODY (first 200 chars)
    """
    s, b = subject.lower(), body.lower()
    score = 0
    early = b[:200]
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in s:      score += 3
        if kw in b:      score += 1
        if kw in early:  score += 2
    return score

def edit_distance_check(sender_email: str) -> int:
    """
    Lookalike domain detection:
      +5 if sender domain is within distance ≤ 2 of any legit domain.
    """
    domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    if not domain:
        return 0
    for legit in LEGIT_DOMAINS:
        if domain != legit and levenshtein_distance(domain, legit) <= 2:
            return 5
    return 0

def suspicious_url_check(subject: str, body: str) -> int:
    """
    Suspicious link detection:
      - +5 for IP-literal links
      - +3 for URLs containing user@host
      - +4 if text mentions a legit domain but links go elsewhere (claimed-domain mismatch)
    """
    score = 0
    urls = extract_urls(body)
    if not urls:
        return 0

    # Find any "claimed" legit domain mentioned in subject/body
    text = f"{subject}\n{body}".lower()
    claimed = [d for d in LEGIT_DOMAINS if d in text]

    for url in urls:
        host = url_domain(url)

        if is_ip_literal(host):
            score += 5
        if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
            score += 3

        # Claimed-domain mismatch heuristic
        for d in claimed:
            if not domain_matches(host, d):
                score += 4
                break

    return score

# ---------- Final classifier ----------

def classify_email(sender: str, subject: str, body: str):
    """
    Combine all rule scores.
      Threshold: score >= 10 -> "Phishing" else "Safe"
    """
    score  = whitelist_check(sender)
    score += keyword_check(subject, body)
    score += edit_distance_check(sender)
    score += suspicious_url_check(subject, body)

    label = "Phishing" if score > 4 else "Safe"  # was 10
    return label, score
