
# Can tahan weird inputs, and read settings from config.json.

import re
from config import CONFIG, load_config_to_rules

# Global settings
DEBUG = False           # if True, will print reasons per email (for debugging lah)

# --- Helpers (compiled once) ---
# Regex faster if compile once. Below detect URLs and email domains.

URL_RE   = re.compile(r"(https?://|www\.)", re.I)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", re.I)


# Attachments that usually cannot make it (dangerous). See already must add score.
RISKY_ATTACH_RE = re.compile(r"\.(?:exe|scr|bat|cmd|js|vbs|jar|msi|hta|html?|zip|7z|rar)\b", re.I)

# --- Helper Functions ---

def extract_domain(sender: str) -> str:
    """Extract domain from sender email address."""
    from config import _safe_str
    s = _safe_str(sender)
    m = EMAIL_RE.search(s)
    return (m.group(1) or "").lower() if m else ""

# --- Main Check Functions ---

def whitelist_check(sender: str, text_l: str) -> tuple[bool, float, list]:
    """Check if sender domain is whitelisted and detect suspicious URLs."""
    dom = extract_domain(sender)
    if dom and any(dom.endswith(ld) for ld in CONFIG.get("legit_domains", [])):
        if DEBUG: 
            print("[HAM] whitelisted domain:", dom)
        return True, 0.0, ["whitelisted"]
    
    # If not whitelisted, check for suspicious URLs
    score = 0.0
    reasons = []
    
    # Get weight from config
    T = CONFIG.get("thresholds", {}) if isinstance(CONFIG, dict) else {}
    URL_W = float(T.get("url_weight", 0.8))
    
    # If got URL, then add score (no keyword requirement)
    if URL_RE.search(text_l):
        score += URL_W
        reasons.append("url")
    
    return False, score, reasons

def keyword_check(text_l: str) -> tuple[float, list]:
    """Check for suspicious keywords in email text."""
    score = 0.0
    reasons = []
    
    # Get weight from config
    T = CONFIG.get("thresholds", {}) if isinstance(CONFIG, dict) else {}
    KW_W = float(T.get("keyword_weight", 1.0))
    
    # Count keywords
    keywords = CONFIG.get("keywords", [])
    kw_hits = sum(1 for k in keywords if k in text_l)
    
    if kw_hits:
        score += kw_hits * KW_W
        reasons.append(f"kw×{kw_hits}")
    
    return score, reasons

def edit_distance_check(text_l: str) -> tuple[float, list]:
    """Check for typosquat domains using Levenshtein distance."""
    score = 0.0
    reasons = []
    
    # Get configuration
    legit_domains = CONFIG.get("legit_domains", [])
    T = CONFIG.get("thresholds", {}) if isinstance(CONFIG, dict) else {}
    max_distance = int(T.get("max_levenshtein_distance", 2))  # Default max distance of 2
    
    # Extract domains from text using regex
    import re
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    found_domains = re.findall(domain_pattern, text_l)
    
    for found_domain in found_domains:
        found_domain_lower = found_domain.lower()
        
        # Check if it's already in legit domains (exact match)
        if found_domain_lower in legit_domains:
            continue
            
        # Check Levenshtein distance against all legit domains
        min_distance = float('inf')
        closest_legit = ""
        
        for legit_domain in legit_domains:
            # Inline Levenshtein distance calculation using dynamic programming
            a, b = found_domain_lower, legit_domain
            la, lb = len(a), len(b)
            dp = [[0]*(lb+1) for _ in range(la+1)]
            for i in range(la+1): dp[i][0] = i
            for j in range(lb+1): dp[0][j] = j
            for i in range(1, la+1):
                for j in range(1, lb+1):
                    cost = 0 if a[i-1] == b[j-1] else 1
                    dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
            distance = dp[la][lb]
            
            if distance < min_distance:
                min_distance = distance
                closest_legit = legit_domain
        
        # If distance is small enough, it's likely a typosquat
        if min_distance <= max_distance and min_distance > 0:
            score += 1.0
            reasons.append(f"typosquat({found_domain}~{closest_legit},d={min_distance})")
    
    return score, reasons


def safety_checks(subject_l: str, text_l: str, kw_hits: int) -> tuple[float, list]:
    """Check for risky attachments, safe terms, and apply guardrails."""
    score = 0.0
    reasons = []
    
    # Get weights from config
    T = CONFIG.get("thresholds", {}) if isinstance(CONFIG, dict) else {}
    SAFE_DOWN = float(T.get("safe_downweight", 0.9))
    
    # Risky attachments (like .exe). Add small score.
    if RISKY_ATTACH_RE.search(text_l):
        score += 0.8
        reasons.append("risky_attachment")
    
    # Newsletter / digest type — downweight a bit to avoid false alarm.
    safe_terms = CONFIG.get("safe_terms", [])
    if any(s in subject_l for s in safe_terms) or any(s in text_l for s in safe_terms):
        score -= SAFE_DOWN
        reasons.append("safe_down")
    
    # Guardrail — only 0/1 keyword, likely harmless. Minus a bit.
    if kw_hits <= 1:
        score -= 0.5
        reasons.append("guardrail")
    
    # Gentle nudge — if already got multiple keywords, add 0.2 to push borderline.
    if kw_hits >= 2:
        score += 0.2
        reasons.append("adaptive")
    
    return score, reasons

def classify_email(sender, subject, body):
    """Classify email as Ham or Phishing based on scoring rules."""
    try:
        from config import _safe_str, _log_err
        # Convert everything to lowercase — later matching more shiok.
        subject_l = _safe_str(subject).lower()
        body_l = _safe_str(body).lower()
        text_l = (subject_l + "\n" + body_l)

        # Get threshold from config
        T = CONFIG.get("thresholds", {}) if isinstance(CONFIG, dict) else {}
        PHISH_SCORE = float(T.get("phish_score", 1.5))

        # Get kw_hits for checks that need it
        keywords = CONFIG.get("keywords", [])
        kw_hits = sum(1 for k in keywords if k in text_l)

        # 1) Whitelist check + URL check — if whitelisted, return immediately
        is_whitelisted, whitelist_score, whitelist_reasons = whitelist_check(sender, text_l)
        if is_whitelisted:
            return "Ham", whitelist_score

        # Initialize total score and reasons
        total_score = whitelist_score  # Include URL score from whitelist check
        all_reasons = whitelist_reasons

        # 2) Keyword check
        kw_score, kw_reasons = keyword_check(text_l)
        total_score += kw_score
        all_reasons.extend(kw_reasons)

        # 3) Edit distance check (typosquat domains)
        edit_score, edit_reasons = edit_distance_check(text_l)
        total_score += edit_score
        all_reasons.extend(edit_reasons)

        # 5) Other checks (attachments, safe terms, guardrails)
        safety_score, other_reasons = safety_checks(subject_l, text_l, kw_hits)
        total_score += safety_score
        all_reasons.extend(other_reasons)

        # Final decision — if score high enough, call Phishing. Else Ham.
        label = "Phishing" if total_score >= PHISH_SCORE else "Ham"
        if DEBUG:
            print(f"[{label}] score={round(total_score,2)} reasons={all_reasons}")
        return label, round(float(total_score), 2)

    except Exception as e:
        # Aiya, something exploded. Log and return safe default.
        import traceback
        _log_err("classify_email error: " + repr(e))
        _log_err(traceback.format_exc())
        return "Ham", -999.0
