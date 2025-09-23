"""Rule engine for the phishing detector.

Provides:
- Config lists for whitelisted domains, known brands, and suspicious keywords
- Small runtime helpers to add items to those lists
- Individual rule functions that score various phishing signals
- A coordinator function `run_all_rules` that aggregates rule outputs
"""

from typing import Dict, List, Tuple  # import generic types
from utils import (  # import helpers
    extract_name_and_email,  # parse from header
    extract_domain,  # get domain from email
    levenshtein_distance,  # compute edit distance
    extract_urls,  # find urls
    extract_domain_from_url,  # get host from url
    is_ipv4_address,  # detect ipv4 host
)  # end imports

WHITELISTED_DOMAINS: List[str] = [  # safe domains
    "gmail.com", "outlook.com", "yahoo.com", "apple.com", "microsoft.com", "amazon.com"
]  # list end

KNOWN_BRAND_NAMES: List[str] = [  # brand names
    "apple", "microsoft", "amazon", "google", "paypal", "netflix"
]  # list end

SUSPICIOUS_KEYWORDS: List[str] = [  # suspicious keywords
    "urgent", "verify", "account", "click", "password", "login",
    "update", "confirm", "security", "invoice", "payment", "limited", "suspend"
]  # list end

def _normalize_items(values: List[str]) -> List[str]:
    """Return normalized non-empty items (lowercase, stripped) from ``values``."""
    normalized: List[str] = []
    for v in values:
        if v is None:
            continue
        nv = str(v).strip().lower()
        if nv:
            normalized.append(nv)
    return normalized

def add_whitelisted_domains(values: List[str]) -> int:
    """Add domains to the whitelist after normalization and de-duplication.

    Returns the number of newly added domains.
    """
    added = 0
    for domain in _normalize_items(values):
        if domain not in WHITELISTED_DOMAINS:
            WHITELISTED_DOMAINS.append(domain)
            added += 1
    return added

def add_known_brand_names(values: List[str]) -> int:
    """Add brand names after normalization and de-duplication.

    Returns the number of newly added brand names.
    """
    added = 0
    for brand in _normalize_items(values):
        if brand not in KNOWN_BRAND_NAMES:
            KNOWN_BRAND_NAMES.append(brand)
            added += 1
    return added

def add_suspicious_keywords(values: List[str]) -> int:
    """Add suspicious keywords after normalization and de-duplication.

    Returns the number of newly added keywords.
    """
    added = 0
    for kw in _normalize_items(values):
        if kw not in SUSPICIOUS_KEYWORDS:
            SUSPICIOUS_KEYWORDS.append(kw)
            added += 1
    return added

def whitelist_check(sender_email: str) -> Tuple[int, str]:
    """Score based on whether the sender's domain is whitelisted.

    Returns a tuple of (score, details).
    """
    domain = extract_domain(sender_email)  # sender domain
    if domain in WHITELISTED_DOMAINS:  # whitelist hit
        return 0, f"Sender domain '{domain}' is whitelisted."  # score 0
    return 5, f"Sender domain '{domain}' is not in whitelist."  # score 5

def keyword_position_score(subject: str, body: str) -> Tuple[int, str]:
    """Weighted keyword scoring with positional emphasis and a score cap.

    Returns a tuple of (score, details).
    """
    subj = subject.lower()  # normalize subject
    bod = body.lower()  # normalize body
    score = 0  # initialize
    details: List[str] = []  # collect details
    for kw in SUSPICIOUS_KEYWORDS:  # iterate keywords
        subj_count = subj.count(kw)  # occurrences in subject
        first_body_count = bod[:200].count(kw)  # early body count
        rest_body_count = bod[200:].count(kw)  # rest body count
        kw_score = subj_count * 3 + first_body_count * 2 + rest_body_count * 1  # weighted
        if kw_score > 0:  # if present
            score += kw_score  # add
            details.append(
                f"Keyword '{kw}' - subject:{subj_count}, early-body:{first_body_count}, "
                f"rest:{rest_body_count}, score:+{kw_score}"
            )
    if score > 12:  # cap score
        details.append("Capped keyword score at 12 to balance scoring.")  # note cap
        score = 12  # apply cap
    return score, "\n".join(details) if details else "No suspicious keywords found."  # return

def edit_distance_check(sender_name: str, sender_email: str) -> Tuple[int, str]:
    """Detect lookalikes via edit distance for domain and sender display name.

    Returns a tuple of (score, details).
    """
    domain = extract_domain(sender_email)  # sender domain
    best_domain_distance = 99  # init large
    for legit in WHITELISTED_DOMAINS + ["google.com", "paypal.com", "netflix.com"]:  # compare set
        d = levenshtein_distance(domain, legit)  # distance
        if d < best_domain_distance:  # keep min
            best_domain_distance = d  # update
    best_name_distance = 99  # init large
    name_norm = sender_name.lower().strip()  # normalize name
    if name_norm:  # only if present
        for brand in KNOWN_BRAND_NAMES:  # compare brands
            dn = levenshtein_distance(name_norm, brand)  # distance
            if dn < best_name_distance:  # keep min
                best_name_distance = dn  # update
    score = 0  # init score
    if 1 <= best_domain_distance <= 2:  # near but not equal
        score += 5  # suspicious domain lookalike
    if 1 <= best_name_distance <= 2:  # near brand
        score += 4  # suspicious name lookalike
    details = f"Min domain distance: {best_domain_distance}; Min name distance: {best_name_distance}"  # detail
    return score, details  # return

def suspicious_url_detection(text: str, sender_email: str) -> Tuple[int, str]:
    """Score risky URLs: IP hosts, brand mismatches, sender-domain mismatches.

    Returns a tuple of (score, details).
    """
    urls = extract_urls(text)  # find urls
    if not urls:  # none found
        return 0, "No URLs found."  # zero
    sender_domain = extract_domain(sender_email)  # sender domain
    score = 0  # init
    detail_lines: List[str] = []  # details
    for u in urls:  # each url
        host = extract_domain_from_url(u)  # host part
        if is_ipv4_address(host):  # if ipv4
            score += 5  # risk
            detail_lines.append(f"URL '{u}' uses IP address host '{host}' (+5)")  # detail
            continue  # next url
        for brand in KNOWN_BRAND_NAMES:  # brand hints
            if brand in u.lower() and (not host.endswith(brand + ".com")):  # mismatch
                score += 4  # risk
                detail_lines.append(  # detail
                    f"URL '{u}' mentions '{brand}' but host '{host}' does not end with {brand}.com (+4)"
                )  # end append
                break  # avoid double counting
        if sender_domain and (not host.endswith(sender_domain)):  # sender mismatch
            score += 3  # small risk
            detail_lines.append(  # detail
                f"URL host '{host}' does not match sender domain '{sender_domain}' (+3)"
            )  # end append
    if score > 12:  # cap
        detail_lines.append("Capped URL score at 12 to balance scoring.")  # note cap
        score = 12  # apply cap
    return score, "\n".join(detail_lines)  # return

def run_all_rules(parsed: Dict[str, str]) -> Dict[str, object]:
    """Run all rules and aggregate results with a final classification."""
    sender_name, sender_email = extract_name_and_email(parsed.get("from", ""))  # name,email
    subject = parsed.get("subject", "")  # subject
    body = parsed.get("body", "")  # body
    w_score, w_details = whitelist_check(sender_email)  # whitelist check
    k_score, k_details = keyword_position_score(subject, body)  # keyword score
    e_score, e_details = edit_distance_check(sender_name, sender_email)  # edit distance score
    u_score, u_details = suspicious_url_detection(subject + "\n" + body, sender_email)  # url score
    total = w_score + k_score + e_score + u_score  # sum total
    classification = "Phishing" if total >= 10 else "Safe"  # classify
    return {  # structured result
        "whitelist": {"score": w_score, "details": w_details},  # whitelist result
        "keywords": {"score": k_score, "details": k_details},  # keywords result
        "edit_distance": {"score": e_score, "details": e_details},  # edit result
        "urls": {"score": u_score, "details": u_details},  # urls result
        "total_score": total,  # final score
        "classification": classification,  # label
    }  # end dict