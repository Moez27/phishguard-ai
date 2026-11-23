"""Display of an analysis result (verdict, score, indicators, advice)."""

from __future__ import annotations

import html

import streamlit as st

from components.cards import stat_tile
from components.theme import STATUS_COLORS, verdict_text
from services.history import history_target
from services.reports import export_filename, result_csv
from services.risk_engine import AnalysisResult
from services.signals import Signal

_SEVERITY_BADGE = {
    "high": '<span class="pg-badge crit">HIGH</span>',
    "medium": '<span class="pg-badge warn">MEDIUM</span>',
    "low": '<span class="pg-badge muted">LOW</span>',
}


def _verdict_banner(result: AnalysisResult, suspect: float, phishing: float) -> None:
    verdict = result.verdict.value
    color = STATUS_COLORS[verdict]
    score_pct = round(result.risk_score * 100)
    st.markdown(
        f"""
<div class="pg-verdict" style="--pg-verdict-color:{color}" role="status">
  <div class="pg-verdict-top">
    <div class="pg-verdict-label">{html.escape(verdict_text(verdict))}</div>
    <div class="pg-verdict-score">{score_pct}<small> / 100 risk</small></div>
  </div>
  <div class="pg-verdict-summary">{html.escape(result.summary)}</div>
  <div class="pg-meter" aria-label="Risk score {score_pct} out of 100">
    <div class="pg-meter-marker" style="left:calc({result.risk_score * 100:.1f}% - 2px)"></div>
    <div class="pg-meter-scale" style="left:0%;transform:none">0</div>
    <div class="pg-meter-scale" style="left:{suspect * 100:.0f}%">Suspicious {suspect:.0%}</div>
    <div class="pg-meter-scale" style="left:{phishing * 100:.0f}%">Phishing {phishing:.0%}</div>
    <div class="pg-meter-scale" style="left:100%;transform:translateX(-100%)">100</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def _signals_list(signals: list[Signal]) -> None:
    if not signals:
        st.markdown(
            '<div class="pg-card"><div class="pg-detail">No rule-based indicator was found. '
            "This does not prove the content is safe.</div></div>",
            unsafe_allow_html=True,
        )
        return
    rows = "".join(
        f'<div class="pg-signal"><div class="pg-signal-badge">{_SEVERITY_BADGE[s.severity]}</div>'
        f'<div><div class="pg-signal-title">{html.escape(s.title)}</div>'
        f'<div class="pg-signal-detail">{html.escape(s.detail)}</div></div>'
        f'<div class="pg-signal-weight">+{s.weight:.0%}</div></div>'
        for s in signals
    )
    st.markdown(f'<div class="pg-card">{rows}</div>', unsafe_allow_html=True)


def render_result(
    result: AnalysisResult, suspect: float, phishing: float, record_id: str | None
) -> None:
    """Render a complete analysis result."""
    for warning in result.warnings:
        st.info(warning, icon="ℹ️")

    _verdict_banner(result, suspect, phishing)

    c1, c2, c3 = st.columns(3)
    with c1:
        if result.ml_probability is not None:
            stat_tile("AI model probability", f"{result.ml_probability:.0%}",
                      result.model_algorithm or "")  # fmt: skip
        elif result.analysis_type == "url":
            stat_tile("AI model probability", "n/a", "URLs are analysed with rules only")
        else:
            stat_tile("AI model probability", "Unavailable", "Rule-based result only")
    with c2:
        stat_tile("Rule-based score", f"{result.rule_score:.0%}", "Combined explainable indicators")
    with c3:
        stat_tile("Indicators found", str(len(result.signals)), "Listed below, strongest first")

    left, right = st.columns([3, 2], gap="large")
    with left:
        st.markdown("#### Indicators")
        _signals_list(result.signals)
        if result.ml_terms:
            st.markdown("#### Words that raised the AI score")
            chips = "".join(
                f'<span class="pg-chip">{html.escape(t)}</span>' for t in result.ml_terms
            )
            st.markdown(chips, unsafe_allow_html=True)
            st.caption(
                "Terms of this email with the largest contribution towards *phishing* in the "
                "model. They explain the model, they are not proof by themselves."
            )
    with right:
        st.markdown("#### Recommendations")
        st.markdown("\n".join(f"- {r}" for r in result.recommendations))
        st.markdown("#### How to read this score")
        st.caption(
            "The score combines an AI model trained on public corpora with explainable rules. "
            "It is an estimate to support your decision, not a certainty: a low score never "
            "guarantees that a message or link is safe."
        )

    meta = [f"Analysed in {result.duration_ms:.0f} ms"]
    if result.model_version:
        meta.append(f"model {result.model_version}")
    meta.append(f"saved to history as ID {record_id}" if record_id else "not saved to history")
    info, action = st.columns([3, 1], vertical_alignment="center")
    info.caption(" · ".join(meta))
    action.download_button(
        "Download this result (CSV)",
        data=result_csv(result, record_id, history_target(result)),
        file_name=export_filename(f"{result.analysis_type}_result"),
        mime="text/csv",
        icon="⬇️",
        width="stretch",
        key=f"download_{result.analysis_type}_{record_id or 'unsaved'}",
    )
