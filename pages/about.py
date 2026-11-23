"""About page: purpose, method, security, data credits and limitations."""

import streamlit as st

from components.theme import APP_VERSION, page_header
from config.settings import get_settings
from services.system_status import read_model_metadata

settings = get_settings()
meta = read_model_metadata(settings)

page_header(
    "About PhishGuard AI",
    "A local platform that analyses emails and URLs and estimates their phishing risk.",
    eyebrow="About",
)

st.markdown(
    """
PhishGuard AI is an engineering project in **defensive cybersecurity** (Project 7, *phishing
email detection with AI*). It helps an analyst decide whether an email or a link is likely to be
phishing, and explains **why**.
"""
)

st.markdown("### How an analysis works")
cols = st.columns(5)
steps = [
    ("1 · Validate", "Size limits, binary detection, allowed URL schemes."),
    ("2 · Extract", "Subject, body, links, sender, attachment names. Nothing is opened."),
    ("3 · AI model", "TF-IDF + linear SVM trained on SpamAssassin and Nazario corpora."),
    ("4 · Rules", "Explainable indicators: credentials, urgency, link structure, spoofing."),
    ("5 · Score", "Combined risk score, verdict, indicators and recommendations."),
]
for col, (title, text) in zip(cols, steps, strict=True):
    with col, st.container(border=True):
        st.markdown(f"**{title}**")
        st.caption(text)

st.markdown(
    f"""
**Verdicts:** ✔ *Likely legitimate* (risk < {settings.suspect_threshold:.0%}) ·
⚠ *Suspicious* · ✖ *Likely phishing* (risk ≥ {settings.phishing_threshold:.0%}).
The AI model alone can raise an email to *Suspicious* at most. *Likely phishing* requires concrete
indicators as well, which limits false alarms on modern legitimate emails.
"""
)

st.markdown("### Security and privacy")
st.markdown(
    """
- Submitted links are **never opened**, resolved or sent to an external service; they are shown
  *defanged* (`hxxp://example[.]com`).
- Attachments are identified by their **name only**: never decoded, saved or executed.
- The history keeps **minimal metadata** (no email text by default); entries can be deleted.
- The application listens on **this computer only** (localhost).
- Inputs are size-limited and protected against injection and regex denial-of-service;
  CSV exports are protected against formula injection; the model file is integrity-checked.
"""
)

st.markdown("### Data and credits")
st.markdown(
    """
- **SpamAssassin Public Corpus** — Apache SpamAssassin project (legitimate emails, *ham*).
- **Nazario Phishing Corpus** — © Jose Nazario, licensed under **CC BY 4.0** (phishing emails).
- Built with Python, Streamlit, scikit-learn, pandas, NumPy, Plotly, BeautifulSoup and tldextract.
"""
)

st.markdown("### Limitations")
st.markdown(
    """
- The training corpora are partly old (2002 onward); performance on today's emails may be lower
  than the test-set metrics.
- No URL reputation or blacklist service is queried.
- A result is an **estimate to support a decision**, never a guarantee that content is safe.
"""
)
model_line = (
    f"AI model {meta['model_version']} ({meta['algorithm']})" if meta else "AI model: not trained"
)
st.caption(f"PhishGuard AI v{APP_VERSION} · {model_line} · local mode")
