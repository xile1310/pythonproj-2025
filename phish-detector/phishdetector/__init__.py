from .rules import (  # re-export selected helpers for convenience
    add_whitelisted_domains,
    add_known_brand_names,
    add_suspicious_keywords,
)

# expose submodules and helpers for simple imports
__all__ = [
    "utils",
    "rules",
    "add_whitelisted_domains",
    "add_known_brand_names",
    "add_suspicious_keywords",
]
