"""History page: search, filter, inspect, delete and export recorded analyses."""

import json

import pandas as pd
import streamlit as st

from components.theme import page_header, verdict_text
from config.settings import get_settings
from database.repository import (
    TYPES,
    VERDICTS,
    HistoryFilter,
    count_analyses,
    delete_all_analyses,
    delete_analyses,
    get_stats,
    list_analyses,
    top_signal_codes,
)
from services.reports import export_filename, history_csv, stats_csv
from services.signals import signal_label

DISPLAY_LIMIT = 500
TYPE_LABELS = {"email": "✉ Email", "url": "🔗 URL"}

settings = get_settings()
db = settings.db_path

page_header(
    "Analysis history",
    "Search, filter, inspect, delete and export the analyses recorded on this machine.",
    eyebrow="History",
)
st.caption(
    "🔒 Only minimal data is stored: date, type, verdict, scores, indicators and the URL host "
    "or sender domain. The email text is not kept"
    + (
        " (storage of email bodies is ENABLED in the configuration)."
        if settings.store_email_body
        else "."
    )  # fmt: skip
)

# Message from a previous run (e.g. after a deletion)
if flash := st.session_state.pop("history_flash", None):
    st.success(flash, icon="✅")

if get_stats(db).total == 0:
    st.info("The history is empty. Analyses appear here automatically.", icon="📭")
    c1, c2, _ = st.columns([1, 1, 2])
    c1.page_link("pages/email_analysis.py", label="Analyse an email", icon="✉️")
    c2.page_link("pages/url_analysis.py", label="Analyse a URL", icon="🔗")
    st.stop()

# --- Filters -------------------------------------------------------------------
with st.container(border=True):
    c1, c2, c3 = st.columns([2, 2, 1.4])
    search = c1.text_input(
        "Search",
        placeholder="Domain, ID or indicator (e.g. urgency)",
        max_chars=100,
        key="history_search",
    )
    verdicts = c2.multiselect(
        "Verdict", VERDICTS, format_func=verdict_text, key="history_verdicts",
        placeholder="All verdicts",
    )  # fmt: skip
    types = c3.multiselect(
        "Type", TYPES, format_func=lambda t: TYPE_LABELS[t], key="history_types",
        placeholder="All types",
    )  # fmt: skip
    d1, d2, _ = st.columns([1, 1, 2.4])
    date_from = d1.date_input("From (UTC)", value=None, key="history_from", format="DD/MM/YYYY")
    date_to = d2.date_input("To (UTC)", value=None, key="history_to", format="DD/MM/YYYY")

if date_from and date_to and date_from > date_to:
    st.error("The 'From' date must be on or before the 'To' date.", icon="🚫")
    st.stop()

flt = HistoryFilter(
    verdicts=tuple(verdicts),
    types=tuple(types),
    date_from=date_from,
    date_to=date_to,
    search=search,
)
n_match = count_analyses(db, flt)
records = list_analyses(db, flt, limit=DISPLAY_LIMIT)

# --- Toolbar: count + exports --------------------------------------------------
left, mid, right = st.columns([2, 1, 1], vertical_alignment="bottom")
shown = f" (showing the latest {DISPLAY_LIMIT})" if n_match > DISPLAY_LIMIT else ""
left.markdown(f"**{n_match:,}** matching analys{'is' if n_match == 1 else 'es'}{shown}")
mid.download_button(
    "Export results (CSV)",
    data=history_csv(list_analyses(db, flt)) if n_match else b"",
    file_name=export_filename("history"),
    mime="text/csv",
    icon="⬇️",
    disabled=n_match == 0,
    help="All analyses matching the current filters.",
    width="stretch",
)
right.download_button(
    "Export statistics (CSV)",
    data=stats_csv(get_stats(db), top_signal_codes(db, limit=20)),
    file_name=export_filename("statistics"),
    mime="text/csv",
    icon="📈",
    help="Totals, verdict shares and most frequent indicators (whole history).",
    width="stretch",
)

if not records:
    st.info("No analysis matches these filters.", icon="🔎")
    st.stop()

# --- Table ---------------------------------------------------------------------
table = pd.DataFrame(
    {
        "Date (UTC)": [r.created_at.replace(tzinfo=None) for r in records],
        "Type": [TYPE_LABELS[r.analysis_type] for r in records],
        "Target": [r.target or "—" for r in records],
        "Verdict": [verdict_text(r.verdict) for r in records],
        "Risk": [round(r.risk_score * 100) for r in records],
        "Indicators": [len(r.signal_codes) for r in records],
        "ID": [r.public_id for r in records],
    }
)
table_key = f"history_table_{st.session_state.get('history_table_version', 0)}"
event = st.dataframe(
    table,
    hide_index=True,
    width="stretch",
    on_select="rerun",
    selection_mode="multi-row",
    key=table_key,
    column_config={
        "Date (UTC)": st.column_config.DatetimeColumn(format="DD MMM YYYY, HH:mm"),
        "Risk": st.column_config.ProgressColumn(
            "Risk", min_value=0, max_value=100, format="%d / 100"
        ),
        "Target": st.column_config.TextColumn(help="URL host or email sender domain"),
    },
)
selected = [records[i] for i in event.selection.rows if i < len(records)]
st.caption("Select rows (left checkbox) to see details or delete them.")


def _reset_selection(message: str) -> None:
    st.session_state["history_flash"] = message
    st.session_state["history_table_version"] = st.session_state.get("history_table_version", 0) + 1
    st.rerun()


@st.dialog("Delete selected analyses")
def _confirm_delete(ids: list[str]) -> None:
    st.write(f"Permanently delete **{len(ids)}** analys{'is' if len(ids) == 1 else 'es'}?")
    st.caption("This cannot be undone.")
    c1, c2 = st.columns(2)
    if c1.button("Delete", type="primary", width="stretch"):
        removed = delete_analyses(db, ids)
        _reset_selection(f"{removed} analys{'is' if removed == 1 else 'es'} deleted.")
    if c2.button("Cancel", width="stretch"):
        st.rerun()


@st.dialog("Erase the entire history")
def _confirm_delete_all(total: int) -> None:
    st.write(f"This permanently deletes **all {total:,} analyses** from the local database.")
    sure = st.checkbox("I understand that this cannot be undone.")
    c1, c2 = st.columns(2)
    if c1.button("Erase everything", type="primary", disabled=not sure, width="stretch"):
        removed = delete_all_analyses(db)
        _reset_selection(f"History erased ({removed:,} analyses deleted).")
    if c2.button("Cancel", width="stretch"):
        st.rerun()


# --- Selection details & actions ---------------------------------------------
if selected:
    if st.button(f"🗑 Delete selected ({len(selected)})", type="secondary"):
        _confirm_delete([r.public_id for r in selected])

    if len(selected) == 1:
        r = selected[0]
        with st.container(border=True):
            st.markdown(
                f"**{verdict_text(r.verdict)}** · risk {r.risk_score:.0%} · ID `{r.public_id}`"
            )
            c1, c2, c3 = st.columns(3)
            c1.metric("Rule-based score", f"{r.rule_score:.0%}")
            c2.metric(
                "AI probability",
                "n/a" if r.ml_probability is None else f"{r.ml_probability:.0%}",
            )
            c3.metric("Indicators", len(r.signal_codes))
            if r.signal_codes:
                st.markdown("**Indicators:** " + ", ".join(signal_label(c) for c in r.signal_codes))
            st.caption(
                f"Recorded {r.created_at:%d %b %Y %H:%M} UTC · "
                f"model {r.model_version or 'not used'}"
            )
            with st.expander("Stored metadata"):
                st.code(json.dumps(r.metadata, indent=2), language="json")

with st.expander("Danger zone"):
    st.caption("Erase every recorded analysis (for example before a demonstration).")
    if st.button("Erase entire history…"):
        _confirm_delete_all(get_stats(db).total)
