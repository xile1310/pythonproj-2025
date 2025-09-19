"""Streamlit UI for the phishing detector.

Responsibilities:
- Present title/description and a brief help panel
- Accept file upload and trigger analysis
- Display per-rule results and final classification
- Provide sidebar controls to add whitelist domains, brands, and keywords at runtime
"""

import streamlit as st  # import streamlit for UI
import os  # import os for filesystem paths
from phishdetector.utils import save_and_rename_to_txt, read_text_file  # IO helpers
from main import analyze_email_text  # analyzer
from phishdetector.rules import (  # runtime configuration helpers and constants
    add_whitelisted_domains,
    add_known_brand_names,
    add_suspicious_keywords,
    WHITELISTED_DOMAINS,
    KNOWN_BRAND_NAMES,
    SUSPICIOUS_KEYWORDS,
)

st.set_page_config(page_title="Phishing Detector (Rule-Based)")  # page config
st.title("Phishing Email Detector (Rule-Based)")  # app title
st.write("Upload any email file. The app will rename it to .txt, process it, and run checks.")  # description

# Help modal toggle state
if "show_help" not in st.session_state:
    st.session_state["show_help"] = False

# Place help toggle button directly under the description
if st.button("How this works"):
    st.session_state["show_help"] = not st.session_state["show_help"]

# Pseudo-modal help panel (toggle by button)
if st.session_state.get("show_help", False):
    with st.container():
        st.markdown("""
**How this detector works**

- Upload a file; we read its text and parse basic headers.
- We run rule checks and assign scores:
  - Whitelist Check: 0 if sender domain is in the safe list, else +4.
  - Keyword Detection & Position Scoring: suspicious words weighted higher in subject/early body (capped).
  - Edit Distance Check: detects lookalike domains/names similar to known brands/domains.
  - Suspicious URL Detection: flags IP-host links, brand mismatches, and host ≠ sender domain (capped).
- Final Risk Scoring combines all rule scores; total ≥ 10 → Phishing, else Safe.
""")

# Uploader below the help button/panel
uploaded = st.file_uploader("Upload an email file (any type)", type=None)  # uploader control
# Sidebar: Runtime configuration for whitelist/brands/keywords
with st.sidebar:
    st.header("Configure Rules (Optional)")
    st.caption("Add items at runtime. Inputs are lowercased and deduplicated.")

    domains_input = st.text_area(
        "Whitelisted domains",
        placeholder="example.com, mycompany.com",
        height=70,
    )
    if st.button("Add domains"):
        items = [p.strip() for p in domains_input.replace("\n", ",").split(",") if p.strip()]
        if items:
            added = add_whitelisted_domains(items)
            st.success(f"Added {added} new domain(s). Total: {len(WHITELISTED_DOMAINS)}")
        else:
            st.info("Enter one or more domains, separated by commas or new lines.")

    brands_input = st.text_area(
        "Known brand names",
        placeholder="google, paypal",
        height=70,
    )
    if st.button("Add brands"):
        items = [p.strip() for p in brands_input.replace("\n", ",").split(",") if p.strip()]
        if items:
            added = add_known_brand_names(items)
            st.success(f"Added {added} new brand(s). Total: {len(KNOWN_BRAND_NAMES)}")
        else:
            st.info("Enter one or more brands, separated by commas or new lines.")

    keywords_input = st.text_area(
        "Suspicious keywords",
        placeholder="wire transfer, gift card",
        height=70,
    )
    if st.button("Add keywords"):
        items = [p.strip() for p in keywords_input.replace("\n", ",").split(",") if p.strip()]
        if items:
            added = add_suspicious_keywords(items)
            st.success(f"Added {added} new keyword(s). Total: {len(SUSPICIOUS_KEYWORDS)}")
        else:
            st.info("Enter one or more keywords, separated by commas or new lines.")

if st.button("Analyze Email"):  # analyze button
    if uploaded is None:  # if no file uploaded
        st.warning("Please upload a file first.")  # prompt user
    else:  # have a file
        raw_bytes = uploaded.getvalue()  # read bytes from uploaded file
        upload_dir = os.path.join(os.getcwd(), "uploads")  # path to uploads dir
        final_path = save_and_rename_to_txt(upload_dir, uploaded.name, raw_bytes)  # save and rename to .txt
        text = read_text_file(final_path)  # read text from saved file
        results = analyze_email_text(text)  # run full analysis

        st.subheader("Results")  # section header

        st.markdown(f"**Whitelist Check Score:** {results['whitelist']['score']}")  # whitelist score
        st.code(results['whitelist']['details'])  # whitelist details

        st.markdown(f"**Keyword Position Check Score:** {results['keywords']['score']}")  # keyword score
        st.code(results['keywords']['details'])  # keyword details

        st.markdown(f"**Edit Distance Check Score:** {results['edit_distance']['score']}")  # edit distance score
        st.code(results['edit_distance']['details'])  # edit distance details

        st.markdown(f"**Suspicious URL Detection Score:** {results['urls']['score']}")  # url score
        st.code(results['urls']['details'])  # url details

        st.markdown(f"**Final Score:** {results['total_score']}")  # total score
        st.markdown(f"**Classification:** {results['classification']}")  # classification result

st.caption("Score > 10 => Phishing. This is a simple educational tool.")  # footer note
