# rules.py — hardened against bad inputs; config-driven
# Can tahan weird inputs, and read settings from config.json.

import json, os, re, traceback

CONFIG = {}
DEBUG = False           # if True, will print reasons per email (for debugging lah)
LOG_PATH = "rules_errors.log"
_LOG_COUNT = 0
_LOG_LIMIT = 200        # don’t spam log until pengsan; cap at 200 lines

# --- Helpers (compiled once) ---
# Regex faster if compile once. Below detect URLs and email domains.

URL_RE   = re.compile(r"(https?://|www\.)", re.I)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", re.I)

# Some common phishy phrases. See already must be careful.
CONTEXT_PHRASES = [
    "verify your account", "verify your identity", "reset your password",
    "confirm your identity", "confirm your account", "update your information",
    "unusual activity", "security alert", "suspended account", "account locked",
    "expired session", "validate your credentials", "update payment",
    "billing problem", "login to your account", "click here to"
]

# Typosquat domains — look like legit but actually fake one.
SUSPICIOUS_DOMAINS = [
    "paypall.com", "micros0ft.com", "goog1e.com", "faceb00k.com",
    "apple-id-verify.com", "secure-login.com", "support-security.com"
]

# Attachments that usually cannot make it (dangerous). See already must add score.
RISKY_ATTACH_RE = re.compile(r"\.(?:exe|scr|bat|cmd|js|vbs|jar|msi|hta|html?|zip|7z|rar)\b", re.I)

def _safe_str(x):
    """Convert anything to safe string. If bytes, decode; if None, return empty.
    Won’t throw error — steady lah.
    """
    try:
        if x is None:
            return ""
        if isinstance(x, bytes):
            return x.decode("utf-8", errors="replace")
        return str(x)
    except Exception:
        return ""

def _log_err(msg):
    """Log quietly. If too many logs already, don’t overdo."""
    global _LOG_COUNT
    if _LOG_COUNT >= _LOG_LIMIT:
        return
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg.rstrip() + "\n")
        _LOG_COUNT += 1
    except Exception:
        # Logging also can fail — nvm, just swallow.
        pass

def load_config_to_rules(path: str = "config.json"):
    """Load settings from config.json; lowercase all the list values.
    If file missing or broken, use safe defaults. Don’t crash hor.
    """
    global CONFIG
    try:
        if not os.path.isfile(path):
            CONFIG = {"legit_domains": [], "keywords": [], "safe_terms": [], "thresholds": {}}
            print(f"[WARN] config file {path} not found, using defaults")
            return

        with open(path, "r", encoding="utf-8") as f:
            CONFIG = json.load(f)

        # Make sure everything lowercase — matching easier, no headache.
        for key in ("legit_domains", "keywords", "safe_terms"):
            CONFIG[key] = [(_safe_str(x)).lower() for x in CONFIG.get(key, [])]

        # thresholds maybe not there — create lah.
        CONFIG.setdefault("thresholds", {})
        print(f"[OK] rules loaded: {len(CONFIG['keywords'])} keywords, "
              f"{len(CONFIG['legit_domains'])} legit domains, "
              f"{len(CONFIG['safe_terms'])} safe terms")
    except Exception as e:
        _log_err("load_config_to_rules error: " + repr(e))
        _log_err(traceback.format_exc())
        # fallback — steady bom pi pi
        CONFIG = {"legit_domains": [], "keywords": [], "safe_terms": [], "thresholds": {}}

def _domain_from(sender: str) -> str:
    """Extract domain from sender email. If cannot find, return empty.
    Example: 'Alice <a@paypal.com>' -> 'paypal.com'
    """
    s = _safe_str(sender)
    m = EMAIL_RE.search(s)
    return (m.group(1) or "").lower() if m else ""

def classify_email(sender, subject, body):
    """Main function. Return (label, score).
    Never throw exception one — if something spoil, we log and return ('Ham', -999.0).
    """
    try:
        # Convert everything to lowercase — later matching more shiok.
        subject_l = _safe_str(subject).lower()
        body_l    = _safe_str(body).lower()
        text_l    = (subject_l + "\n" + body_l)

        # Read weights/thresholds from config. If not provided, use default.
        T           = CONFIG.get("thresholds", {}) if isinstance(CONFIG, dict) else {}
        PHISH_SCORE = float(T.get("phish_score", 1.5))   # final decision line — score ≥ this => Phishing
        KW_W        = float(T.get("keyword_weight", 1.0))  # weight for keywords (from config.json)
        CTX_W       = float(T.get("context_weight", 1.3))  # weight for phrases above
        URL_W       = float(T.get("url_weight", 0.8))      # small boost if got URL + other signals
        SAFE_DOWN   = float(T.get("safe_downweight", 0.9)) # subtract a bit if looks like newsletter/digest

        # 1) Whitelist check — sender domain in legit list? If yes, straightaway Ham.
        dom = _domain_from(sender)
        if dom and any(dom.endswith(ld) for ld in CONFIG.get("legit_domains", [])):
            if DEBUG: print("[HAM] whitelisted domain:", dom)
            return "Ham", 0.0

        score = 0.0
        reasons = []  # if DEBUG True, we store reasons for human look-see.

        # 2) Count keywords + context phrases
        keywords = CONFIG.get("keywords", [])
        kw_hits  = sum(1 for k in keywords if k in text_l)    # how many sus keywords found
        ctx_hits = sum(1 for c in CONTEXT_PHRASES if c in text_l)  # how many context phrases

        if kw_hits:
            score += kw_hits * KW_W; reasons.append(f"kw×{kw_hits}")
        if ctx_hits:
            score += ctx_hits * CTX_W; reasons.append(f"ctx×{ctx_hits}")

        # 3) If got URL and also got keyword/context, then add small boost
        # Why like that? Cos random URL not necessarily phish; but URL + sus wording, then sus lor.
        if URL_RE.search(text_l) and (kw_hits + ctx_hits) > 0:
            score += URL_W; reasons.append("url")

        # 4) Typosquat domains appear in the text? Add small score.
        if any(sd in text_l for sd in SUSPICIOUS_DOMAINS):
            score += 1.0; reasons.append("typosquat")

        # 5) Risky attachments (like .exe). Add small score.
        if RISKY_ATTACH_RE.search(text_l):
            score += 0.8; reasons.append("risky_attachment")

        # 6) Newsletter / digest type — downweight a bit to avoid false alarm.
        safe_terms = CONFIG.get("safe_terms", [])
        if any(s in subject_l for s in safe_terms) or any(s in text_l for s in safe_terms):
            score -= SAFE_DOWN; reasons.append("safe_down")

        # 7) Guardrail — only 0/1 keyword AND no context, likely harmless. Minus a bit.
        if ctx_hits == 0 and kw_hits <= 1:
            score -= 0.5; reasons.append("guardrail")

        # 8) Gentle nudge — if already got multiple keywords OR at least one context, add 0.2 to push borderline.
        if kw_hits >= 2 or ctx_hits >= 1:
            score += 0.2; reasons.append("adaptive")

        # Final decision — if score high enough, call Phishing. Else Ham.
        label = "Phishing" if score >= PHISH_SCORE else "Ham"
        if DEBUG:
            print(f"[{label}] score={round(score,2)} reasons={reasons}")
        return label, round(float(score), 2)

    except Exception as e:
        # Aiya, something exploded. Log and return safe default.
        _log_err("classify_email error: " + repr(e))
        _log_err(traceback.format_exc())
        return "Ham", -999.0
