
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
    """Write configuration to disk as JSON.

    Args:
        path: File path to write to (e.g., config.json).
        cfg: Configuration dictionary to persist.

    Notes:
        Silently ignores I/O errors.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass
#take domain and keywords from config.json
def apply_cfg(cfg: dict) -> None:
    """Apply configuration values into in-memory rule sets.

    Populates `LEGIT_DOMAINS` and `SUS_KEYWORDS` from the provided
    configuration dict, trimming whitespace and normalizing to lowercase.

    Args:
        cfg: Configuration with keys "legit_domains" and "keywords".
    """
    # Clear existing legit domain set then replicate with clean values from configuration
    LEGIT_DOMAINS.clear()
    LEGIT_DOMAINS.update({d.strip().lower() for d in cfg.get("legit_domains", []) if d.strip()}) # remove spaces & lowercases
    # Clear existing suspicious keyword set then replicate with clean values from configuration
    SUS_KEYWORDS.clear()                                                                         # Get list from config 
    SUS_KEYWORDS.update({k.strip().lower() for k in cfg.get("keywords", []) if k.strip()})       # Ignore empty strings 

def load_config_to_rules(path: str = CONFIG_PATH) -> None:
    """
    load config.json if it does not exist create a new one using DEFAULT_CONFIGURATION
    else if is different format it will fix it.
    """
    if os.path.exists(path):
        try:
            # Try to open and load exisiting connfig.json
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            # If reading fails, use the default configuration as fallback
            cfg = DEFAULT_CONFIGURATION.copy()
    else:
        # If file does not exist, create a new one using default configuration
        cfg = DEFAULT_CONFIGURATION.copy()
        persist(path, cfg)

    # Migrate old schema → new (whitelist + brands → legit_domains)
    if "legit_domains" not in cfg:
        # Get old keys "whitelist" and "brands", otherwise empty lists
        wl = cfg.get("whitelist", []) or []
        br = cfg.get("brands", []) or []
        # Merge whitelist and brands into single sorted set named "legit_domains"
        cfg["legit_domains"] = sorted({*wl, *br})
        # Remove old keys from config as they're not used 
        cfg.pop("whitelist", None)
        cfg.pop("brands", None)
        # Apply configuration
        persist(path, cfg)

    cfg.setdefault("legit_domains", [])
    cfg.setdefault("keywords", [])
    apply_cfg(cfg)

def save_rules_to_config(path: str = CONFIG_PATH) -> None:
    """Persist current sets to config.json."""
    cfg = {
        "legit_domains": sorted(LEGIT_DOMAINS),  # Known legitimate domains
        "keywords": sorted(SUS_KEYWORDS),        # Suspicious keywords
    }
    # Save config file to disk
    persist(path, cfg)

def reset_to_defaults(path: str = CONFIG_PATH) -> None:
    """Reset sets + config.json to DEFAULT_CONFIG."""
    # Apply default configuration 
    apply_cfg(DEFAULT_CONFIGURATION)
    # Save default configuration to disk
    persist(path, DEFAULT_CONFIGURATION)

# Load config when module is imported
load_config_to_rules()

# ---------- Small helpers ----------
# Methods used in main rules functions

def levenshtein_distance(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings.

    Each insertion, deletion, or substitution costs 1.

    Args:
        a: First string.
        b: Second string.

    Returns:
        The minimum number of single-character edits to transform `a` into `b`.
    """
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
    """Extract all HTTP/HTTPS URLs from a text blob.

    Args:
        text: Arbitrary text possibly containing URLs.

    Returns:
        List of URL substrings starting with http:// or https:// up to the next whitespace.
    """
# Used in suspicious_url_check function
# Uses re.findall with pattern r"http[s]?://\S+": 
# Captures every non-whitespace character after (http:// or https://) up to the next whitespace.

    return re.findall(r"http[s]?://\S+", text)

def url_domain(url: str) -> str:
    """Return the lowercase hostname component of a URL.

    Strips embedded credentials and port, if present.

    Args:
        url: Absolute URL string.

    Returns:
        Hostname (e.g., "example.com") or empty string on parse failure.
    """
# Used in suspicious_url_check function
# Purpose is to extract the domain from the URL
# Domain is the value after the @ and Before the :

    try:
        netloc = urlparse(url).netloc
        if "@" in netloc:  # strip credentials
            netloc = netloc.split("@", 1)[-1] # Split the netloc at @, take the last element
        if ":" in netloc:  # strip port
            netloc = netloc.split(":", 1)[0]# Split the netloc at :, take the first element
        return netloc.lower()
    except Exception:
        return ""

def is_ip_literal(host: str) -> bool:
    """Check if a hostname looks like a bare IPv4 address.

    Args:
        host: Host component (no scheme/path).

    Returns:
        True if it matches N.N.N.N (digits-and-dots) format; False otherwise.

    Note:
        This validates only the pattern, not octet ranges (0–255).
    """
# Used in suspicious_url_check function
# Checks if the IP address is a bare IPv4 address (e.g., "192.168.0.1")
# Pattern enforces the format, which is exactly four numeric groups separated by dots
    return bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host))

def domain_matches(host: str, root: str) -> bool:
    """Determine if `host` equals `root` or is its subdomain.

    Case-insensitive comparison used for matching claimed brand domains.

    Args:
        host: Hostname from a URL (e.g., "mail.example.com").
        root: Legit base domain (e.g., "example.com").

    Returns:
        True if host == root or host ends with "." + root; False otherwise.
    """
# Used in suspicious_url_check function
# Checks if host is the same as root or a subdomain of it
    host, root = host.lower(), root.lower()
    return host == root or host.endswith("." + root)

# ---------- Individual rules (scored) ----------

def whitelist_check(sender_email: str) -> int:
    """Score based on whether sender domain is whitelisted.

    Args:
        sender_email: Full sender address (e.g., "user@domain.com").

    Returns:
        0 if the domain is in `LEGIT_DOMAINS`; otherwise 2.
    """
    # Domain Extration and Check
    # Extracts domain by splitting at "@", take last element
    # if no @,returns empty string
    domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
     #compares it with value in LEGIT_DOMAINS to determine score
    return 0 if domain in LEGIT_DOMAINS else 2


def keyword_check(subject: str, body: str) -> int:
    """Score email based on presence/location of suspicious keywords.

    Args:
        subject: Email subject line.
        body: Email body text.

    Returns:
        Integer score: +3 per keyword in subject, +1 in body, +2 if within
        the first 200 body characters.
    """
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
    """Detect lookalike sender domains using edit distance.

    Args:
        sender_email: Full sender address.

    Returns:
        +5 if the sender's domain is within Levenshtein distance ≤ 2 of any
        domain in `LEGIT_DOMAINS`; otherwise 0. Returns 0 if no domain.
    """
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
    """Score suspicious patterns in URLs contained in the email body.

    Rules:
      - +5 for IP-literal links
      - +3 for URLs containing user@host
      - +4 if text mentions a legit domain but links go elsewhere

    Args:
        subject: Email subject line.
        body: Email body text.

    Returns:
        Cumulative integer score across all URLs found in the body.
    """

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
    """Classify an email as "Phishing" or "Safe" using rule-based scoring.

    Combines scores from whitelist, keyword, edit-distance, and URL rules.

    Args:
        sender: Sender email address.
        subject: Email subject line.
        body: Email body text.

    Returns:
        Tuple of (label, score) where label is "Phishing" or "Safe" and
        score is the integer total from all rules.
    """
    # Combine all rule scores.
    # If score >= 10 -> "Phishing" else "Safe"

    score  = whitelist_check(sender) # Checks if sender is on the whitelist
    score += keyword_check(subject, body) # Add score from suspicious keywords
    score += edit_distance_check(sender) # Add score if sender comes from a legit domain
    score += suspicious_url_check(subject, body) # Add score from suspicious URLs in the email body

    label = "Phishing" if score > 10 else "Safe"
    return label, score
