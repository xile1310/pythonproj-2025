import os, json, traceback

# This is the default configuration if json file not exist
DEFAULT_CONFIGURATION = {
    "legit_domains": ["singapore.tech.edu.sg","paypal.com","google.com"],
    "keywords": ["urgent", "verify", "account", "password", "click"],
    "safe_terms": ["newsletter"],
    "thresholds": {"phish_score": 1.5, "keyword_weight": 1.0, "url_weight": 0.8, "safe_downweight": 0.9}
}

# Global CONFIG for newrules.py compatibility
CONFIG = {}

# Always keep config.json next to this module, regardless of CWD
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

# In-memory configuration sets used by rules
LEGIT_DOMAINS = set()
SUS_KEYWORDS = set()

# Helper functions for newrules.py compatibility
def _safe_str(x):
    """Convert input to safe string, handling bytes and None values."""
    try:
        if x is None:
            return ""
        if isinstance(x, bytes):
            return x.decode("utf-8", errors="replace")
        return str(x)
    except Exception:
        return ""

def _log_err(msg):
    """Log error message to file quietly."""
    try:
        with open("rules_errors.log", "a", encoding="utf-8") as f:
            f.write(msg.rstrip() + "\n")
    except Exception:
        pass

def persist(path: str, cfg: dict) -> None:
    """Write configuration to disk as JSON file."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def apply_cfg(cfg: dict) -> None:
    """Apply configuration values to in-memory rule sets."""
    LEGIT_DOMAINS.clear()
    LEGIT_DOMAINS.update({d.strip().lower() for d in cfg.get("legit_domains", []) if d.strip()})

    SUS_KEYWORDS.clear()
    SUS_KEYWORDS.update({k.strip().lower() for k in cfg.get("keywords", []) if k.strip()})

def load_config_to_rules(path: str = CONFIG_PATH) -> None:
    """Load configuration from JSON file with schema migration."""
    global CONFIG
    
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

    # Set defaults for new structure
    cfg.setdefault("legit_domains", [])
    cfg.setdefault("keywords", [])
    cfg.setdefault("safe_terms", [])
    cfg.setdefault("thresholds", {})
    
    # Apply to legacy sets (for backward compatibility)
    apply_cfg(cfg)
    
    # Update global CONFIG for newrules.py
    try:
        # Make sure everything lowercase — matching easier, no headache.
        for key in ("legit_domains", "keywords", "safe_terms"):
            cfg[key] = [(_safe_str(x)).lower() for x in cfg.get(key, [])]

        CONFIG = cfg
        print(f"[OK] rules loaded: {len(CONFIG['keywords'])} keywords, "
              f"{len(CONFIG['legit_domains'])} legit domains, "
              f"{len(CONFIG['safe_terms'])} safe terms")
    except Exception as e:
        _log_err("load_config_to_rules error: " + repr(e))
        _log_err(traceback.format_exc())
        # fallback — steady bom pi pi
        CONFIG = {"legit_domains": [], "keywords": [], "safe_terms": [], "thresholds": {}}

def save_rules_to_config(path: str = CONFIG_PATH) -> None:
    """Save current rule sets to config.json."""
    # Save from CONFIG dict (which the web app modifies), not from legacy sets
    cfg = {
        "legit_domains": sorted(CONFIG.get("legit_domains", [])),
        "keywords": sorted(CONFIG.get("keywords", [])),
        "safe_terms": sorted(CONFIG.get("safe_terms", [])),
        "thresholds": CONFIG.get("thresholds", {})
    }
    persist(path, cfg)

def reset_to_defaults(path: str = CONFIG_PATH) -> None:
    """Reset configuration to default values."""
    apply_cfg(DEFAULT_CONFIGURATION)
    persist(path, DEFAULT_CONFIGURATION)

# Load config when module is imported (preserve previous behavior)
load_config_to_rules()


