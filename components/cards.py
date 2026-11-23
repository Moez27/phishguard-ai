"""Reusable card and tile components."""

from __future__ import annotations

import html

import streamlit as st

from services.system_status import ComponentStatus


def status_card(status: ComponentStatus) -> None:
    """Render a component status card (state shown by icon + text, not colour alone)."""
    if status.available:
        badge = '<span class="pg-badge ok">✔ READY</span>'
    else:
        badge = '<span class="pg-badge warn">⚠ NOT AVAILABLE</span>'
    next_step = (
        f'<div class="pg-next">Next step: {html.escape(status.next_step)}</div>'
        if status.next_step
        else ""
    )
    st.markdown(
        f'<div class="pg-card"><h4>{html.escape(status.name)}</h4>{badge}'
        f'<div class="pg-detail">{html.escape(status.detail)}</div>{next_step}</div>',
        unsafe_allow_html=True,
    )


def stat_tile(label: str, value: str, sub: str = "", dot_color: str | None = None) -> None:
    """A KPI tile. ``dot_color`` adds a colour key next to the label (never alone)."""
    dot = f'<span class="pg-dot" style="background:{dot_color}"></span>' if dot_color else ""
    sub_html = f'<div class="pg-tile-sub">{html.escape(sub)}</div>' if sub else ""
    st.markdown(
        f'<div class="pg-tile"><div class="pg-tile-label">{dot}{html.escape(label)}</div>'
        f'<div class="pg-tile-value">{html.escape(value)}</div>{sub_html}</div>',
        unsafe_allow_html=True,
    )
