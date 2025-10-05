import os, json

# This is the default configuration if json file not exist
DEFAULT_CONFIGURATION = {
    "legit_domains": ["singapore.tech.edu.sg","paypal.com","google.com"],
    "keywords": ["urgent", "verify", "account", "password", "click"],
}

# Always keep config.json next to this module, regardless of CWD
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

# In-memory configuration sets used by rules
LEGIT_DOMAINS = set()
SUS_KEYWORDS = set()

def persist(path: str, cfg: dict) -> None:
    """Write configuration to disk as JSON.

    Silently ignores I/O errors to maintain previous behavior.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def apply_cfg(cfg: dict) -> None:
    """Apply configuration values into in-memory rule sets.

    Populates `LEGIT_DOMAINS` and `SUS_KEYWORDS` from the provided
    configuration dict, trimming whitespace and normalizing to lowercase.
    """
    LEGIT_DOMAINS.clear()
    LEGIT_DOMAINS.update({d.strip().lower() for d in cfg.get("legit_domains", []) if d.strip()})

    SUS_KEYWORDS.clear()
    SUS_KEYWORDS.update({k.strip().lower() for k in cfg.get("keywords", []) if k.strip()})

def load_config_to_rules(path: str = CONFIG_PATH) -> None:
    """
    Load config.json. If it does not exist, create a new one using DEFAULT_CONFIGURATION.
    If an older schema is detected, migrate it.
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
    """Reset sets + config.json to DEFAULT_CONFIGURATION."""
    apply_cfg(DEFAULT_CONFIGURATION)
    persist(path, DEFAULT_CONFIGURATION)

# Load config when module is imported (preserve previous behavior)
load_config_to_rules()


