"""
This code contains rules that our phishing detector will be using
"""

import os, json, re
from urllib.parse import urlparse

# This is the default configuration if json file not exist
DEFAULT_CONFIGURATION = {
    "legit_domains": ["singapore.tech.edu.sg","paypal.com","google.com"],
    "keywords": ["urgent", "verify", "account", "password", "click"],
}
CONFIG_PATH = "config.json"

LEGIT_DOMAINS = set()
SUS_KEYWORDS = set()

#config helper functions
def persist(path: str, cfg: dict) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass
#take domain and keywords from config.json
def apply_cfg(cfg: dict) -> None:
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
