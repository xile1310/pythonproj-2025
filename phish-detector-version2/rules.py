
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
# Always keep config.json next to this module, regardless of CWD
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

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
# Methods used in main rules functions

def levenshtein_distance(a: str, b: str) -> int:
# Used in edit_distance_check helper
# Purpose is to determine whether is similar to legit domain
# Returns the minimum number of edits needed
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
# Used in suspicious_url_check function
# Uses re.findall with pattern r"http[s]?://\S+": 
# Captures every non-whitespace character after (http:// or https://) up to the next whitespace.

    return re.findall(r"http[s]?://\S+", text)

def url_domain(url: str) -> str:
# Used in suspicious_url_check function
# Purpose is to extract the domain from the URL
# Domain is the value after the @ and Before the :
# Split the netloc at @, take the last element
# Split the netloc at :, take the first element

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
# Used in suspicious_url_check function
# Checks if the IP address is a bare IPv4 address (e.g., "192.168.0.1")
# Pattern enforces the format, which is exactly four numeric groups separated by dots
    return bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host))

def domain_matches(host: str, root: str) -> bool:
# Used in suspicious_url_check function
# Checks if host is the same as root or a subdomain of it
    host, root = host.lower(), root.lower()
    return host == root or host.endswith("." + root)

# ---------- Individual rules (scored) ----------

def whitelist_check(sender_email: str) -> int:
    # Domain Extration and Check
    # Extracts domain by splitting at "@", take last element
    # if no @,returns empty string
    domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
     #compares it with value in LEGIT_DOMAINS to determine score
    return 0 if domain in LEGIT_DOMAINS else 2


def keyword_check(subject: str, body: str) -> int:
    # Dynamic Scoring system
    # +3 in subject (s), +1 in body(s), +2 if in first 200 body characters(early)
    s, b = subject.lower(), body.lower()
    score = 0
    early = b[:200]
    # Loops through the keywords(kw) in SUS_KEYWORDS and adds into "score"
    for kw in SUS_KEYWORDS:
        if kw in s:      score += 3
        if kw in b:      score += 1
        if kw in early:  score += 2
    return score

def edit_distance_check(sender_email: str) -> int:
    # Domain Lookalike Checker
    # Extracts domain by splitting at "@", take last element
    # if no @,returns empty string
    domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    if not domain:
        return 0
    # Loops over values in LEGIT_DOMAINS
    # If its not in LEGIT_DOMAINS, computes the Levenshtein distance.
    # Grace area of 2 is given to prevent false positives
    for legit in LEGIT_DOMAINS:
        if domain != legit and levenshtein_distance(domain, legit) <= 2:
            return 5
    return 0

def suspicious_url_check(subject: str, body: str) -> int:

    score = 0
    # Extract all http/https URLs from the email body text
    # If no URLs are present, there is nothing to score
    urls = extract_urls(body)
    if not urls:
        return 0


    # Create a list of legit domains explicitly mentioned in the text (claimed brands)
    text = f"{subject}\n{body}".lower()
    claimed = [d for d in LEGIT_DOMAINS if d in text]

    # Loops over each URL extracted
    for url in urls:
        # Extract the hostname from the URL using helper function
        host = url_domain(url)

        # Determine ip literal using helper function , socre based on 
        # +5 if the URL’s host is a raw IPv4 address
        # +3 if the URL contains user@host before the first slash
        if is_ip_literal(host):
            score += 5
        if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
            score += 3

        # Claimed-domain mismatch heuristic
        # If the domains mentioned in the text are not the same as the URL's host, score +4
        for d in claimed:
            if not domain_matches(host, d):
                score += 4
                break

    # Return the total accumulated risk score for all URLs
    return score

# ---------- Final classifier ----------

def classify_email(sender: str, subject: str, body: str):
    # Combine all rule scores.
    # If score >= 10 -> "Phishing" else "Safe"

    score  = whitelist_check(sender) # Checks if sender is on the whitelist
    score += keyword_check(subject, body) # Add score from suspicious keywords
    score += edit_distance_check(sender) # Add score if sender comes from a legit domain
    score += suspicious_url_check(subject, body) # Add score from suspicious URLs in the email body

    label = "Phishing" if score > 10 else "Safe"
    return label, score
