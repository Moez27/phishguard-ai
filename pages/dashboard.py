"""Dashboard: statistics computed from the analyses actually stored in SQLite."""

import pandas as pd
import streamlit as st

from components.cards import stat_tile, status_card
from components.charts import (
    activity_over_time,
    risk_distribution,
    top_indicators,
    verdict_breakdown,
)
from components.theme import STATUS_COLORS, TYPE_COLORS, page_header, verdict_text
from config.settings import get_settings
from database.repository import daily_activity, get_stats, recent_analyses, risk_scores
from database.repository import top_signal_codes as top_codes
from services.signals import signal_label
from services.system_status import collect_status, read_model_metadata

ACTIVITY_DAYS = 30
CHART_CONFIG = {"displayModeBar": False}

settings = get_settings()
stats = get_stats(settings.db_path)

page_header(
    "Security dashboard",
    "Overview of the analyses recorded on this machine.",
    eyebrow="Overview",
)

# --- Empty state -------------------------------------------------------------
if stats.total == 0:
    st.info(
        "No analysis has been recorded yet. Statistics appear here as soon as you analyse "
        "an email or a URL.",
        icon="📭",
    )
    c1, c2, _ = st.columns([1, 1, 2])
    c1.page_link("pages/email_analysis.py", label="Analyse an email", icon="✉️")
    c2.page_link("pages/url_analysis.py", label="Analyse a URL", icon="🔗")
else:
    # --- KPI tiles -----------------------------------------------------------
    def pct(n: int) -> str:
        return f"{n / stats.total:.0%} of analyses"

    k = st.columns(5)
    with k[0]:
        stat_tile(
            "Total analyses",
            f"{stats.total:,}",
            f"{stats.by_type['email']:,} emails · {stats.by_type['url']:,} URLs",
        )
    for col, verdict in zip(k[1:4], ("phishing", "suspect", "legitimate"), strict=True):
        with col:
            n = stats.by_verdict[verdict]
            stat_tile(verdict_text(verdict), f"{n:,}", pct(n), STATUS_COLORS[verdict])
    with k[4]:
        stat_tile(
            "Average risk score",
            f"{stats.average_risk:.0%}",
            f"Last analysis {stats.last_analysis_at:%d %b %Y %H:%M} UTC",
        )
    st.write("")

    # --- Charts --------------------------------------------------------------
    left, right = st.columns([3, 2], gap="medium")
    with left, st.container(border=True):
        st.markdown(f"**Activity — last {ACTIVITY_DAYS} days** (by verdict, UTC)")
        activity = daily_activity(settings.db_path, days=ACTIVITY_DAYS)
        st.plotly_chart(activity_over_time(activity), config=CHART_CONFIG, width="stretch")
    with right, st.container(border=True):
        st.markdown("**Verdict breakdown** (all time)")
        st.plotly_chart(verdict_breakdown(stats.by_verdict), config=CHART_CONFIG, width="stretch")
        st.markdown(
            f'<span class="pg-badge muted" style="border-color:{TYPE_COLORS["email"]}">'
            f"✉ Emails {stats.by_type['email']:,}</span> "
            f'<span class="pg-badge muted" style="border-color:{TYPE_COLORS["url"]}">'
            f"🔗 URLs {stats.by_type['url']:,}</span>",
            unsafe_allow_html=True,
        )

    left, right = st.columns(2, gap="medium")
    with left, st.container(border=True):
        st.markdown("**Risk score distribution**")
        st.plotly_chart(
            risk_distribution(
                risk_scores(settings.db_path),
                settings.suspect_threshold,
                settings.phishing_threshold,
            ),
            config=CHART_CONFIG,
            width="stretch",
        )
    with right, st.container(border=True):
        st.markdown("**Most frequent indicators**")
        codes = top_codes(settings.db_path, limit=8)
        if codes:
            items = [(signal_label(c), n) for c, n in codes]
            st.plotly_chart(top_indicators(items), config=CHART_CONFIG, width="stretch")
        else:
            st.caption("No indicator has been detected in the recorded analyses yet.")

    # --- Recent analyses -----------------------------------------------------
    st.markdown("#### Latest analyses")
    recent = recent_analyses(settings.db_path, limit=10)
    table = pd.DataFrame(
        {
            "Date (UTC)": [r.created_at.replace(tzinfo=None) for r in recent],
            "Type": ["✉ Email" if r.analysis_type == "email" else "🔗 URL" for r in recent],
            "Target": [r.target or "—" for r in recent],
            "Verdict": [verdict_text(r.verdict) for r in recent],
            "Risk": [round(r.risk_score * 100) for r in recent],
            "Indicators": [len(r.signal_codes) for r in recent],
            "ID": [r.public_id for r in recent],
        }
    )
    st.dataframe(
        table,
        hide_index=True,
        width="stretch",
        column_config={
            "Date (UTC)": st.column_config.DatetimeColumn(format="DD MMM YYYY, HH:mm"),
            "Risk": st.column_config.ProgressColumn(
                "Risk", min_value=0, max_value=100, format="%d / 100"
            ),
            "Target": st.column_config.TextColumn(help="URL host or email sender domain"),
        },
    )

# --- Platform status & model -------------------------------------------------
st.markdown("#### Platform status")
statuses = collect_status(settings)
for column, status in zip(st.columns(len(statuses)), statuses, strict=True):
    with column:
        status_card(status)

meta = read_model_metadata(settings)
if meta:
    m = meta["test_metrics"]
    st.caption(
        f"AI model: {meta['algorithm']} · version {meta['model_version']} · "
        f"held-out test set ({meta['dataset']['n_test']:,} emails): "
        f"precision {m['precision_phishing']:.3f}, recall {m['recall_phishing']:.3f}, "
        f"F1 {m['f1_phishing']:.3f}. Measured on public corpora; real-world performance "
        "may be lower (see the evaluation report)."
    )
