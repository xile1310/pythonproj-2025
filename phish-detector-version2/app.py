#!/usr/bin/env python3
#This code is for UI for this phishing detector

import streamlit as st
from rules import (
    classify_email,
    LEGIT_DOMAINS,
    SUS_KEYWORDS,
    load_config_to_rules,
    save_rules_to_config,
    reset_to_defaults,
    whitelist_check,
    keyword_check,
    edit_distance_check,
    suspicious_url_check,
)


def _init_page() -> None:
    """Initialize Streamlit page configuration and title."""
    st.set_page_config(page_title="Phishing Detector",
                       page_icon="📧",
                       layout="centered")
    st.title("📧 Simple Phishing Email Detector")


def _ensure_config_loaded() -> None:
    """Load rules from config.json once per session."""
    if "config_loaded" not in st.session_state:
        load_config_to_rules()
        st.session_state["config_loaded"] = True


def _render_analyze_tab() -> None:
    """Render the Analyze tab and display classification + breakdown."""
    st.subheader("Analyze a Single Email")

    c1, c2 = st.columns(2)
    with c1:
        sender = st.text_input("Sender email", "admin@paypa1.com")
    with c2:
        subject = st.text_input("Subject", "Urgent: Verify your account")

    body = st.text_area(
        "Email body",
        height=200,
        value="Hi Hana, your account is locked. Click http://192.168.0.1 to verify now."
    )

    if st.button("Analyze"):
        label, score = classify_email(sender, subject, body)

        (st.error if label == "Phishing" else st.success)(
            f"Result: {label}  •  Suspicion Score: {score}"
        )

        w = whitelist_check(sender)
        k = keyword_check(subject, body)
        e = edit_distance_check(sender)
        u = suspicious_url_check(subject, body)
        total = w + k + e + u

        st.markdown("**Scoring summary:**")
        st.caption(
            "- Domain not in legit list → +2\n"
            "- Keywords: subject +3, body +1, early body +2\n"
            "- Lookalike of legit domain (edit distance ≤2) → +5\n"
            "- Suspicious URLs (IP / user@host / claimed-domain mismatch) → up to +5/+4\n"
            "- Final: score ≥ 10 → Phishing"
        )

        st.markdown("**Score breakdown:**")
        st.caption(
            f"- Whitelist check: {w:+d}\n"
            f"- Keyword checks: {k:+d}\n"
            f"- Edit-distance (lookalike): {e:+d}\n"
            f"- Suspicious URLs: {u:+d}\n"
            f"- **Total** = {total} (equals Suspicion Score)"
        )


def _render_settings_tab() -> None:
    """Render the Settings tab for managing legit domains and keywords."""
    st.subheader("Manage Rules (persisted to config.json)")
    st.info("Items are normalized to lowercase. Use domains like `example.com` (no http://).")

    st.markdown("### ✅ Legit domains")

    c1, c2 = st.columns([2, 1])
    with c1:
        new_dom = st.text_input("Add domain", placeholder="e.g. sit.singaporetech.edu.sg")
    with c2:
        if st.button("Add domain"):
            if new_dom.strip():
                LEGIT_DOMAINS.add(new_dom.strip().lower())
                save_rules_to_config()
                st.success(f"Added: {new_dom.strip().lower()}")

    if LEGIT_DOMAINS:
        to_remove = st.multiselect("Remove selected", sorted(LEGIT_DOMAINS))
        if st.button("Remove domain(s)"):
            for d in to_remove:
                LEGIT_DOMAINS.discard(d)
            save_rules_to_config()
            st.warning(f"Removed: {', '.join(to_remove) or 'None'}")
    else:
        st.caption("No domains yet.")

    st.divider()

    st.markdown("### 🚩 Suspicious keywords")
    k1, k2 = st.columns([2, 1])
    with k1:
        new_kw = st.text_input("Add keyword", placeholder="e.g., urgent")
    with k2:
        if st.button("Add keyword"):
            if new_kw.strip():
                SUS_KEYWORDS.add(new_kw.strip().lower())
                save_rules_to_config()
                st.success(f"Added: {new_kw.strip().lower()}")

    if SUS_KEYWORDS:
        to_remove_k = st.multiselect("Remove keywords", sorted(SUS_KEYWORDS))
        if st.button("Remove keyword(s)"):
            for k in to_remove_k:
                SUS_KEYWORDS.discard(k)
            save_rules_to_config()
            st.warning(f"Removed: {', '.join(to_remove_k) or 'None'}")
    else:
        st.caption("No keywords yet.")

    st.divider()

    if st.button("Reset to defaults"):
        reset_to_defaults()
        st.success("Settings reset to defaults.")


# --- Main ---
_init_page()
_ensure_config_loaded()

tab_analyze, tab_settings = st.tabs(["🔎 Analyze Email", "⚙️ Settings"])  # created 2 tabs analyze email and settings

with tab_analyze:
    _render_analyze_tab()

with tab_settings:
    _render_settings_tab()
