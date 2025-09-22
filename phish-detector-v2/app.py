#!/usr/bin/env python3
#This code is for UI for this phishing detector

import streamlit as st
from rules import ( #import functions and variables from "rules.py"
    classify_email,
    LEGIT_DOMAINS,
    SUSPICIOUS_KEYWORDS,
    load_config_to_rules,
    save_rules_to_config,
    reset_to_defaults
)

st.set_page_config(page_title="Phishing Detector", #title show in the browser tab
                   page_icon="📧", #Small icon show in the browser tab
                   layout="centered") #page layout in center
st.title("📧 Simple Phishing Email Detector") #big title displayed at the top of the page

# Load configuration
if "config_loaded" not in st.session_state:
    load_config_to_rules() #load saved rules from config.json
    st.session_state["config_loaded"] = True #mark config as already loaded

tab_analyze, tab_settings = st.tabs(["🔎 Analyze Email", "⚙️ Settings"]) #created 2 tabs analyze email and settings

#Tab 1 tab_analyze
with tab_analyze:
    st.subheader("Analyze a Single Email")  #small header

    c1, c2 = st.columns(2)
    with c1:
        sender = st.text_input("Sender email", "scammer@paypa1.com")
    with c2:
        subject = st.text_input("Subject", "Urgent: Verify your account")

    body = st.text_area(
        "Email body",
        height=200,
        value="Hello, your account is locked. Click http://192.168.0.1 to verify now."
    )

    if st.button("Analyze"):
        label, score = classify_email(sender, subject, body)
        (st.error if label == "Phishing" else st.success)(
            f"Result: {label}  •  Suspicion Score: {score}"
        )
        st.markdown("**Scoring summary:**")
        st.caption(
            "- Domain not in legit list → +2\n"
            "- Keywords: subject +3, body +1, early body +2\n"
            "- Lookalike of legit domain (edit distance ≤2) → +5\n"
            "- Suspicious URLs (IP / user@host / claimed-domain mismatch) → up to +5/+4\n"
            "- Final: score ≥ 10 → Phishing"
        )

with tab_settings:
    st.subheader("Manage Rules (persisted to config.json)")
    st.info("Items are normalized to lowercase. Use domains like `example.com` (no http://).")

    # Legit domains (whitelist + reference brands combined)
    st.markdown("### ✅ Legit domains")
    c1, c2 = st.columns([2, 1])
    with c1:
        new_dom = st.text_input("Add domain", placeholder="e.g., ntu.edu.sg")
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

    # Suspicious keywords
    st.markdown("### 🚩 Suspicious keywords")
    k1, k2 = st.columns([2, 1])
    with k1:
        new_kw = st.text_input("Add keyword", placeholder="e.g., urgent")
    with k2:
        if st.button("Add keyword"):
            if new_kw.strip():
                SUSPICIOUS_KEYWORDS.add(new_kw.strip().lower())
                save_rules_to_config()
                st.success(f"Added: {new_kw.strip().lower()}")

    if SUSPICIOUS_KEYWORDS:
        to_remove_k = st.multiselect("Remove keywords", sorted(SUSPICIOUS_KEYWORDS))
        if st.button("Remove keyword(s)"):
            for k in to_remove_k:
                SUSPICIOUS_KEYWORDS.discard(k)
            save_rules_to_config()
            st.warning(f"Removed: {', '.join(to_remove_k) or 'None'}")
    else:
        st.caption("No keywords yet.")

    st.divider()
    if st.button("Reset to defaults"):
        reset_to_defaults()
        st.success("Settings reset to defaults.")
