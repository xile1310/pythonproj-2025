
"""
Rule-based phishing detector (single-list design).
- One list: LEGIT_DOMAINS (used for whitelist + edit-distance lookalikes)
- Suspicious keywords with position scoring (subject heavier + early body bonus)
- Suspicious URL checks (IP literal, user@host, claimed-domain mismatch)
- Config stored in config.json; auto-created/migrated on first run

Public API (unchanged):
- classify_email(sender, subject, body) -> (label, score)
- whitelist_check, keyword_check, edit_distance_check, suspicious_url_check
- LEGIT_DOMAINS, SUSPICIOUS_KEYWORDS (alias SUS_KEYWORDS)
"""

import os, json, re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

# This is the default configuration if json file not exist
DEFAULT_CONFIGURATION = {
    "legit_domains": ["singapore.tech.edu.sg","paypal.com","google.com"],
    "keywords": ["urgent", "verify", "account", "password", "click"],
}
CONFIG_PATH = "config.json"

LEGIT_DOMAINS = set()
SUS_KEYWORDS = set()

# Backwards-compatibility: expose both names
SUSPICIOUS_KEYWORDS = SUS_KEYWORDS

# ---------- Constants (document rule weights/thresholds) ----------

# Keyword scoring
SUBJECT_KEYWORD_WEIGHT = 3
BODY_KEYWORD_WEIGHT = 1
EARLY_BODY_BONUS_WEIGHT = 2
EARLY_BODY_WINDOW = 200

# Lookalike / whitelist scoring
LOOKALIKE_DISTANCE_MAX = 2
EDIT_DISTANCE_SCORE = 5
WHITELIST_MISS_SCORE = 2

# URL heuristics
IP_URL_SCORE = 5
USER_AT_HOST_SCORE = 3
CLAIMED_DOMAIN_MISMATCH_SCORE = 4

# Final classification threshold (strictly greater than)
PHISHING_THRESHOLD = 4

# Precompiled URL regex
URL_PATTERN = re.compile(r"http[s]?://\S+")

# ---------- Config helpers (single source of truth) ----------

def persist(path: str, cfg: Dict[str, List[str]]) -> None:
    """Write configuration to disk (best-effort, no exceptions raised)."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        # Best-effort persistence; intentionally silent to avoid UI crashes
        pass

def apply_cfg(cfg: Dict[str, List[str]]) -> None:
    """Copy cfg values into module-level sets (lowercased)."""
    LEGIT_DOMAINS.clear()
    LEGIT_DOMAINS.update({d.strip().lower() for d in cfg.get("legit_domains", []) if d.strip()})
    SUS_KEYWORDS.clear()
    SUS_KEYWORDS.update({k.strip().lower() for k in cfg.get("keywords", []) if k.strip()})

def load_config_to_rules(path: str = CONFIG_PATH) -> None:
    """
    load config.json if it does not exist create a new one using DEFAULT_CONFIGURATION
    else if is different format it will fix it.
    """
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = DEFAULT_CONFIGURATION.copy()
    else:
        cfg = DEFAULT_CONFIGURATION.copy()
        persist(path, cfg)

    # Migrate old schema → new (whitelist + brands → legit_domains)
    if "legit_domains" not in cfg:
        wl = cfg.get("whitelist", []) or []
        br = cfg.get("brands", []) or []
        cfg["legit_domains"] = sorted({*wl, *br})
        cfg.pop("whitelist", None)
        cfg.pop("brands", None)
        persist(path, cfg)

    cfg.setdefault("legit_domains", [])
    cfg.setdefault("keywords", [])
    apply_cfg(cfg)

def save_rules_to_config(path: str = CONFIG_PATH) -> None:
    """Persist current sets to config.json."""
    cfg = {
        "legit_domains": sorted(LEGIT_DOMAINS),
        "keywords": sorted(SUS_KEYWORDS),
    }
    persist(path, cfg)

def reset_to_defaults(path: str = CONFIG_PATH) -> None:
    """Reset sets + config.json to DEFAULT_CONFIG."""
    apply_cfg(DEFAULT_CONFIGURATION)
    persist(path, DEFAULT_CONFIGURATION)

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

def extract_urls(text: str) -> List[str]:
    """Return all http/https URLs in text."""
    return URL_PATTERN.findall(text)

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
    return 0 if domain in LEGIT_DOMAINS else WHITELIST_MISS_SCORE

def keyword_check(subject: str, body: str) -> int:
    """
    Suspicious keyword scoring:
      - +3 for each keyword in SUBJECT (higher weight)
      - +1 for each keyword anywhere in BODY
      - +2 EXTRA if keyword appears EARLY in BODY (first 200 chars)
    """
    s, b = subject.lower(), body.lower()
    score = 0
    early = b[:EARLY_BODY_WINDOW]
    for kw in SUS_KEYWORDS:
        if kw in s:      score += SUBJECT_KEYWORD_WEIGHT
        if kw in b:      score += BODY_KEYWORD_WEIGHT
        if kw in early:  score += EARLY_BODY_BONUS_WEIGHT
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
        if domain != legit and levenshtein_distance(domain, legit) <= LOOKALIKE_DISTANCE_MAX:
            return EDIT_DISTANCE_SCORE
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
            score += IP_URL_SCORE
        if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
            score += USER_AT_HOST_SCORE

        # Claimed-domain mismatch heuristic
        for d in claimed:
            if not domain_matches(host, d):
                score += CLAIMED_DOMAIN_MISMATCH_SCORE
                break

    return score

# ---------- Final classifier ----------

def classify_email(sender: str, subject: str, body: str) -> Tuple[str, int]:
    """
    Combine all rule scores.
      Threshold: score > PHISHING_THRESHOLD -> "Phishing" else "Safe"
    """
    score  = whitelist_check(sender)
    score += keyword_check(subject, body)
    score += edit_distance_check(sender)
    score += suspicious_url_check(subject, body)

    label = "Phishing" if score > PHISHING_THRESHOLD else "Safe"
    return label, score
