"""URL analysis page (UI only; logic lives in services/)."""

import html

import streamlit as st

from components.results import render_result
from components.theme import defang, page_header
from config.settings import get_settings
from services.analysis import run_url_analysis
from services.examples import URL_EXAMPLES
from services.history import record_analysis
from services.validation import ValidationError

settings = get_settings()

page_header(
    "URL analysis",
    "Check the structure of a suspicious address before anyone clicks on it.",
    eyebrow="Analyse",
)
st.caption(
    "🔒 Offline analysis: the address is read as text only. It is never opened, resolved or "
    "sent to an external service, and no reputation check is performed."
)


def _load_example() -> None:
    name = st.session_state.get("url_example")
    if name in URL_EXAMPLES:
        st.session_state["url_input"] = URL_EXAMPLES[name]


with st.form("url_form", border=True):
    st.text_input(
        "URL to analyse",
        key="url_input",
        max_chars=settings.max_url_length,
        placeholder="e.g. http://login-account.example/verify",
    )
    submitted = st.form_submit_button("Analyse URL", type="primary", icon="🔍")

with st.expander("Try a built-in example"):
    st.selectbox(
        "Synthetic examples (fictitious or harmless addresses)",
        list(URL_EXAMPLES),
        index=None,
        placeholder="Choose an example…",
        key="url_example",
        on_change=_load_example,
    )

if submitted:
    try:
        result = run_url_analysis(st.session_state.get("url_input"), settings)
        record_id = record_analysis(result, settings)
        st.session_state["url_result"] = (result, record_id, st.session_state["url_input"])
    except ValidationError as exc:
        st.session_state.pop("url_result", None)
        st.error(str(exc), icon="🚫")

if "url_result" in st.session_state:
    result, record_id, raw_url = st.session_state["url_result"]
    st.divider()
    st.markdown("**Analysed address** (defanged so it cannot be clicked):")
    st.markdown(
        f'<div class="pg-defanged">{html.escape(defang(raw_url.strip()))}</div>',
        unsafe_allow_html=True,
    )
    st.write("")
    render_result(result, settings.suspect_threshold, settings.phishing_threshold, record_id)

    m = result.metadata
    with st.expander("Extracted features"):
        st.dataframe(
            {
                "Feature": [
                    "Host",
                    "Registered domain",
                    "Scheme",
                    "HTTPS",
                    "IP address host",
                    "Subdomain levels",
                    "Length (characters)",
                ],  # fmt: skip
                "Value": [
                    defang(m["host"]),
                    defang(m["registered_domain"]) or "—",
                    m["scheme"],
                    "Yes" if m["uses_https"] else "No",
                    "Yes" if m["has_ip_host"] else "No",
                    str(m["num_subdomains"]),
                    str(m["length"]),
                ],
            },
            hide_index=True,
            width="stretch",
        )
    if record_id is None:
        st.warning("The result could not be saved to the history database.", icon="⚠️")
