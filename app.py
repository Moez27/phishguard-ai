"""PhishGuard AI — Streamlit entry point.

Run with:  streamlit run app.py
"""

import logging

import streamlit as st

from components.theme import apply_theme, sidebar_brand, sidebar_footer
from config.settings import get_settings

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto",  # expanded on desktop, collapsed on phones
)

settings = get_settings()
logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

apply_theme()
sidebar_brand()

# Only pages that are actually implemented are registered here.
navigation = st.navigation(
    {
        "Overview": [
            st.Page("pages/dashboard.py", title="Dashboard", icon="📊", default=True),
            st.Page("pages/history.py", title="History", icon="🗂️"),
        ],
        "Analyse": [
            st.Page("pages/email_analysis.py", title="Email analysis", icon="✉️"),
            st.Page("pages/url_analysis.py", title="URL analysis", icon="🔗"),
        ],
        "AI model": [
            st.Page("pages/model_evaluation.py", title="Model evaluation", icon="🧪"),
            st.Page("pages/about.py", title="About", icon="ℹ️"),
        ],
    }
)

sidebar_footer()
navigation.run()
