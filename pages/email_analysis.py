"""Email analysis page (UI only; logic lives in services/)."""

import streamlit as st

from components.results import render_result
from components.state import classifier
from components.theme import page_header
from config.settings import get_settings
from services.analysis import run_email_analysis
from services.examples import EMAIL_EXAMPLES
from services.history import record_analysis
from services.validation import ValidationError, validate_upload

settings = get_settings()
model, model_problem = classifier()

page_header(
    "Email analysis",
    "Paste an email (plain text, HTML or a raw email with headers) or upload a .txt file.",
    eyebrow="Analyse",
)
st.caption(
    "🔒 Links are never opened and attachments are never executed. "
    "Only the verdict, scores and minimal metadata are kept in the local history."
)
if model is None:
    st.warning(
        f"The AI model is not available: {model_problem} Analyses will use rules only.",
        icon="⚠️",
    )


def _load_example() -> None:
    name = st.session_state.get("email_example")
    if name in EMAIL_EXAMPLES:
        subject, text = EMAIL_EXAMPLES[name]
        st.session_state["email_subject"] = subject
        st.session_state["email_text"] = text


mode = st.segmented_control(
    "Input method", ["Paste text", "Upload .txt file"], default="Paste text", key="email_mode"
)

with st.form("email_form", border=True):
    subject = st.text_input(
        "Subject (optional)",
        key="email_subject",
        max_chars=500,
        help="Leave empty if the pasted text already contains a 'Subject:' header.",
    )
    uploaded = None
    if mode == "Upload .txt file":
        uploaded = st.file_uploader(
            "Plain-text file (.txt)",
            type=[ext.lstrip(".") for ext in settings.allowed_upload_extensions],
            help=f"Maximum {settings.max_upload_bytes // 1024} KB. The file is read as text only.",
        )
    else:
        st.text_area(
            "Email content",
            key="email_text",
            height=260,
            max_chars=settings.max_email_chars,
            placeholder="Paste the email here…",
        )
    submitted = st.form_submit_button("Analyse email", type="primary", icon="🔍")

if mode != "Upload .txt file":
    with st.expander("Try a built-in example"):
        st.selectbox(
            "Synthetic examples (fictitious domains, safe to use)",
            list(EMAIL_EXAMPLES),
            index=None,
            placeholder="Choose an example…",
            key="email_example",
            on_change=_load_example,
        )

if submitted:
    try:
        if mode == "Upload .txt file":
            if uploaded is None:
                raise ValidationError("Please choose a .txt file to upload.")
            text = validate_upload(uploaded.name, uploaded.getvalue(), settings)
        else:
            text = st.session_state.get("email_text", "")
        with st.spinner("Analysing…"):
            result = run_email_analysis(text, settings, model, subject=subject)
        record_id = record_analysis(result, settings, raw_text=text)
        st.session_state["email_result"] = (result, record_id)
    except ValidationError as exc:
        st.session_state.pop("email_result", None)
        st.error(str(exc), icon="🚫")

if "email_result" in st.session_state:
    result, record_id = st.session_state["email_result"]
    st.divider()
    render_result(result, settings.suspect_threshold, settings.phishing_threshold, record_id)
    if record_id is None:
        st.warning("The result could not be saved to the history database.", icon="⚠️")
