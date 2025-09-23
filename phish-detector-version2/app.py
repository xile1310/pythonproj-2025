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


st.set_page_config(page_title="Phishing Detector", #title show in the browser tab
                   page_icon="📧", #Small icon show in the browser tab
                   layout="centered") #page layout in center
st.title("📧 Simple Phishing Email Detector") #big title displayed at the top of the page

# Load configuration
if "config_loaded" not in st.session_state:
    # load saved rules from config.json
    load_config_to_rules()
    # mark config as already loaded
    st.session_state["config_loaded"] = True

tab_analyze, tab_settings = st.tabs(["🔎 Analyze Email", "⚙️ Settings"]) #created 2 tabs analyze email and settings

#Tab 1 tab_analyze
with tab_analyze:
    st.subheader("Analyze a Single Email")  #small header

    c1, c2 = st.columns(2)
    with c1:
        # A text box to type or paste the sender's email, and default value is admin@paypa1.com
        sender = st.text_input("Sender email", "admin@paypa1.com")
    with c2:
        # A text box for email subject, and default value: Urgent: Verify your account
        subject = st.text_input("Subject", "Urgent: Verify your account")

# A big text area for user to input the message and default value.
    body = st.text_area(
        "Email body",
        height=200,
        value="Hi Hana, your account is locked. Click http://192.168.0.1 to verify now."
    )

#Main action button to analyze
    if st.button("Analyze"):

        label, score = classify_email(sender, subject, body)

        # Display result as you already do
        (st.error if label == "Phishing" else st.success)(
            f"Result: {label}  •  Suspicion Score: {score}"
        )

        # compute per-rule contributions for a clear breakdown
        w = whitelist_check(sender)
        k = keyword_check(subject, body)
        e = edit_distance_check(sender)
        u = suspicious_url_check(subject, body)
        total = w + k + e + u  # should match the score

        #shows how scoring works
        st.markdown("**Scoring summary:**")
        st.caption(
            "- Domain not in legit list → +2\n"
            "- Keywords: subject +3, body +1, early body +2\n"
            "- Lookalike of legit domain (edit distance ≤2) → +5\n"
            "- Suspicious URLs (IP / user@host / claimed-domain mismatch) → up to +5/+4\n"
            "- Final: score ≥ 10 → Phishing"
        )

        # Shows how the score calculated
        st.markdown("**Score breakdown:**")
        st.caption(
            f"- Whitelist check: {w:+d}\n"
            f"- Keyword checks: {k:+d}\n"
            f"- Edit-distance (lookalike): {e:+d}\n"
            f"- Suspicious URLs: {u:+d}\n"
            f"- **Total** = {total} (equals Suspicion Score)"
        )

#Tab 2, manage rules and settings
with tab_settings:
    st.subheader("Manage Rules (persisted to config.json)")
    st.info("Items are normalized to lowercase. Use domains like `example.com` (no http://).")

    # Legit domains (whitelist + reference brands combined)
    st.markdown("### ✅ Legit domains")

    # Add new legit domain
    c1, c2 = st.columns([2, 1])
    with c1:
        new_dom = st.text_input("Add domain", placeholder="e.g. sit.singaporetech.edu.sg")
    with c2:
        if st.button("Add domain"):
            if new_dom.strip():
                LEGIT_DOMAINS.add(new_dom.strip().lower())
                save_rules_to_config()
                st.success(f"Added: {new_dom.strip().lower()}")
    # Remove one or more legit domains
    if LEGIT_DOMAINS:
        to_remove = st.multiselect("Remove selected", sorted(LEGIT_DOMAINS))
        if st.button("Remove domain(s)"):
            for d in to_remove:
                LEGIT_DOMAINS.discard(d)
            save_rules_to_config()
            st.warning(f"Removed: {', '.join(to_remove) or 'None'}")
    else:
        st.caption("No domains yet.") #If the list is empty will show this

    st.divider()

    #Title
    st.markdown("### 🚩 Suspicious keywords")
    #add new suspicious keywords
    k1, k2 = st.columns([2, 1])
    with k1:
        new_kw = st.text_input("Add keyword", placeholder="e.g., urgent")
    with k2:
        if st.button("Add keyword"):
            if new_kw.strip():
                SUS_KEYWORDS.add(new_kw.strip().lower())
                save_rules_to_config()
                st.success(f"Added: {new_kw.strip().lower()}")

    #remove one or more suspicious keywords
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

    #Reset button bring everything back to default settings.
    if st.button("Reset to defaults"):
        reset_to_defaults()
        st.success("Settings reset to defaults.")
