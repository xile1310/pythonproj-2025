#!/usr/bin/env python3

import streamlit as st
import re
import subprocess
import sys
import os
from newrules import (
    classify_email,
    whitelist_check,
    keyword_check,
    edit_distance_check,
)
from config import (
    CONFIG,
    load_config_to_rules,
    save_rules_to_config,
    reset_to_defaults,
)

# Validation functions
def valid_email(email):
    """Validate that email contains both '@' and '.' characters."""
    return "@" in email and "." in email

def validate_inputs(sender, subject, body):
    """Validate UI inputs for sender, subject, and body fields."""
    errors = []
    warnings = []
    
    # Sender email validation (required)
    if not valid_email(sender):
        errors.append("Sender email must contain '@' and '.'")
    
    # Subject validation (warning only)
    if not subject.strip():
        warnings.append("Subject field is empty")
    
    # Body validation (warning only)
    if not body.strip():
        warnings.append("Email body field is empty")
    
    return errors, warnings

def highlight_keywords_in_fields(sender, subject, body):
    """Show highlighted keywords in a separate display area."""
    # Get keywords from config
    keywords = CONFIG.get("keywords", [])
    
    if not keywords:
        return
    
    # Find which keywords are present in the text
    found_keywords = []
    text_lower = (subject + "\n" + body).lower()
    for keyword in keywords:
        if keyword in text_lower:
            found_keywords.append(keyword)
    
    if found_keywords:
        st.markdown("### 🔍 **Keywords Detected in Your Input:**")
        
        # Show highlighted subject
        if subject:
            highlighted_subject = highlight_text(subject, found_keywords)
            st.markdown("**Subject:**")
            st.markdown(highlighted_subject, unsafe_allow_html=True)
        
        # Show highlighted body
        if body:
            highlighted_body = highlight_text(body, found_keywords)
            st.markdown("**Body:**")
            st.markdown(highlighted_body, unsafe_allow_html=True)

def highlight_text(text, keywords):
    """Highlight keywords in text with red background."""
    import re
    
    highlighted_text = text
    for keyword in keywords:
        # Use regex to find and replace keywords (case insensitive)
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        highlighted_text = pattern.sub(
            f'<span style="background-color: #ffcccc; color: #cc0000; font-weight: bold; padding: 1px 2px; border-radius: 2px;">{keyword}</span>',
            highlighted_text
        )
    
    return highlighted_text


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

tab_analyze, tab_settings, tab_help = st.tabs(["🔎 Analyze Email", "⚙️ Settings", "❓ Help"]) #created 3 tabs

#Tab 1 tab_analyze
with tab_analyze:
    st.subheader("Analyze a Single Email")  #small header

    c1, c2 = st.columns(2)
    with c1:
        # A text box to type or paste the sender's email, and default value is admin@paypa1.com
        sender = st.text_input("Sender email", "admin@paypa1.com", help="Must contain '@' and '.'")
    with c2:
        # A text box for email subject, and default value: Urgent: Verify your account
        subject = st.text_input("Subject", "Urgent: Verify your account", help="Optional field")

# A big text area for user to input the message and default value.
    body = st.text_area(
        "Email body",
        height=200,
        value="Hi Hana, your account is locked. Click http://192.168.0.1 to verify now.",
        help="Optional field"
    )

#Main action button to analyze
    if st.button("Analyze"):
        # Validate inputs
        errors, warnings = validate_inputs(sender, subject, body)
        
        # Show warnings (non-blocking)
        if warnings:
            for warning in warnings:
                st.warning(f"⚠️ {warning}")
        
        # Show errors (blocking)
        if errors:
            for error in errors:
                st.error(f"❌ {error}")
            st.stop()  # Prevent analysis from proceeding
        
        # Proceed with analysis if no errors
        label, score = classify_email(sender, subject, body)

        # Display result as you already do
        (st.error if label == "Phishing" else st.success)(
            f"Result: {label}  •  Suspicion Score: {score}"
        )
        
        # Highlight flagged keywords in the input fields
        highlight_keywords_in_fields(sender, subject, body)

        # compute per-rule contributions for a clear breakdown
        is_whitelisted, w_score, w_reasons = whitelist_check(sender, (subject + "\n" + body).lower())
        k_score, k_reasons = keyword_check((subject + "\n" + body).lower())
        e_score, e_reasons = edit_distance_check((subject + "\n" + body).lower())
        total = w_score + k_score + e_score  # should match the score

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
            f"- Whitelist/URL check: {w_score:+.1f}\n"
            f"- Keyword checks: {k_score:+.1f}\n"
            f"- Edit-distance (lookalike): {e_score:+.1f}\n"
            f"- **Total** = {total:.1f} (equals Suspicion Score)"
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
            cleaned = new_dom.strip()
            if not cleaned:
                st.error("Please enter a domain.")
            elif "." not in cleaned:
                st.error("Invalid domain. A domain must contain a '.' (e.g., example.com)")
            else:
                CONFIG["legit_domains"].append(cleaned.lower())
                save_rules_to_config()
                st.success(f"Added: {cleaned.lower()}")
    # Remove one or more legit domains
    if CONFIG.get("legit_domains"):
        to_remove = st.multiselect("Remove selected", sorted(CONFIG["legit_domains"]))
        if st.button("Remove domain(s)"):
            for d in to_remove:
                CONFIG["legit_domains"].remove(d)
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
                CONFIG["keywords"].append(new_kw.strip().lower())
                save_rules_to_config()
                st.success(f"Added: {new_kw.strip().lower()}")

    #remove one or more suspicious keywords
    if CONFIG.get("keywords"):
        to_remove_k = st.multiselect("Remove keywords", sorted(CONFIG["keywords"]))
        if st.button("Remove keyword(s)"):
            for k in to_remove_k:
                CONFIG["keywords"].remove(k)
            save_rules_to_config()
            st.warning(f"Removed: {', '.join(to_remove_k) or 'None'}")
    else:
        st.caption("No keywords yet.")

    st.divider()

    #Title
    st.markdown("### 🛡️ Safe terms")
    #add new safe terms
    s1, s2 = st.columns([2, 1])
    with s1:
        new_safe = st.text_input("Add safe term", placeholder="e.g., newsletter")
    with s2:
        if st.button("Add safe term"):
            if new_safe.strip():
                CONFIG["safe_terms"].append(new_safe.strip().lower())
                save_rules_to_config()
                st.success(f"Added: {new_safe.strip().lower()}")

    #remove one or more safe terms
    if CONFIG.get("safe_terms"):
        to_remove_s = st.multiselect("Remove safe terms", sorted(CONFIG["safe_terms"]))
        if st.button("Remove safe term(s)"):
            for s in to_remove_s:
                CONFIG["safe_terms"].remove(s)
            save_rules_to_config()
            st.warning(f"Removed: {', '.join(to_remove_s) or 'None'}")
    else:
        st.caption("No safe terms yet.")

    st.divider()

    #Reset button bring everything back to default settings.
    if st.button("Reset to defaults"):
        reset_to_defaults()
        st.success("Settings reset to defaults.")

#Tab 3, help and testing
with tab_help:
    
    # Help section
    st.markdown("### 🔧 Testing")
    st.markdown("Run pytest tests to verify the detector is working correctly:")
    
    # Test running section - full width button
    if st.button("🧪 Run All Tests", type="secondary", use_container_width=True):
        with st.spinner("Running tests..."):
            try:
                # Change to test directory and run pytest
                base_dir = os.path.dirname(os.path.abspath(__file__))
                test_dir = os.path.join(base_dir, "test")
                
                # Run pytest command
                result = subprocess.run(
                    [sys.executable, "-m", "pytest", "test_rules.py", "-v"],
                    cwd=test_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    st.success("✅ All tests passed!")
                    st.code(result.stdout)
                else:
                    st.error("❌ Test failures:")
                    st.code(result.stdout)
                    if result.stderr:
                        st.code(result.stderr)
                        
            except subprocess.TimeoutExpired:
                st.error("⏰ Tests timed out after 30 seconds")
            except Exception as e:
                st.error(f"❌ Error running tests: {str(e)}")
                st.info("Make sure pytest is installed: `pip install pytest`")