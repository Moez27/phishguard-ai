"""Visual theme: palette, global CSS and shared layout helpers.

Colour roles (validated with the dataviz palette validator on the dark surface):
* Verdicts use the STATUS palette (good / warning / critical) and are ALWAYS
  shown with an icon and a text label, never by colour alone.
* Email vs URL use categorical slots 1 and 2 (blue, orange).
"""

from __future__ import annotations

import html
import re
from pathlib import Path

import streamlit as st

APP_NAME = "PhishGuard AI"
APP_TAGLINE = "Phishing email & URL risk analysis"
APP_VERSION = "1.0.0"

# --- Palette -----------------------------------------------------------------
PAGE_BG = "#0b1120"
SURFACE = "#111a2e"
BORDER = "#1e2a44"
TEXT = "#e2e8f0"
TEXT_MUTED = "#94a3b8"
GRID = "#1c2740"
ACCENT = "#22d3ee"

STATUS_COLORS = {"legitimate": "#0ca30c", "suspect": "#fab219", "phishing": "#d03b3b"}
TYPE_COLORS = {"email": "#3987e5", "url": "#d95926"}
SERIES_1 = "#3987e5"

VERDICT_ICONS = {"legitimate": "✔", "suspect": "⚠", "phishing": "✖"}
VERDICT_LABELS = {
    "legitimate": "Likely legitimate",
    "suspect": "Suspicious",
    "phishing": "Likely phishing",
}


def verdict_text(verdict: str) -> str:
    """Icon + label, e.g. '✖ Likely phishing'."""
    return f"{VERDICT_ICONS[verdict]} {VERDICT_LABELS[verdict]}"


_CSS = f"""
<style>
:root {{
    --pg-surface: {SURFACE};
    --pg-border: {BORDER};
    --pg-accent: {ACCENT};
    --pg-muted: {TEXT_MUTED};
    --pg-good: {STATUS_COLORS["legitimate"]};
    --pg-warn: {STATUS_COLORS["suspect"]};
    --pg-crit: {STATUS_COLORS["phishing"]};
}}
.block-container {{ padding-top: 2rem; max-width: 1240px; }}

/* Header */
.pg-header h1 {{ font-size: 1.85rem; font-weight: 700; margin: 0 0 .15rem 0;
    letter-spacing: -0.01em; }}
.pg-header p {{ color: var(--pg-muted); margin: 0 0 .6rem 0; }}
.pg-eyebrow {{ color: var(--pg-accent); font-size: .75rem; font-weight: 600;
    letter-spacing: .12em; text-transform: uppercase; }}

/* Cards */
.pg-card {{ background: var(--pg-surface); border: 1px solid var(--pg-border);
    border-radius: 12px; padding: 1rem 1.15rem; height: 100%; }}
.pg-card h4 {{ margin: 0 0 .4rem 0; font-size: 1rem; }}
.pg-detail {{ color: var(--pg-muted); font-size: .88rem; margin: .35rem 0; }}
.pg-next {{ font-size: .85rem; margin-top: .5rem; }}

/* Stat tiles */
.pg-tile {{ background: var(--pg-surface); border: 1px solid var(--pg-border);
    border-radius: 12px; padding: .9rem 1.1rem; height: 100%; }}
.pg-tile .pg-tile-label {{ color: var(--pg-muted); font-size: .8rem; font-weight: 500; }}
.pg-tile .pg-tile-value {{ font-size: 1.75rem; font-weight: 700; line-height: 1.2;
    margin-top: .2rem; font-variant-numeric: tabular-nums; }}
.pg-tile .pg-tile-sub {{ color: var(--pg-muted); font-size: .8rem; margin-top: .15rem; }}
.pg-tile .pg-dot {{ display: inline-block; width: .6rem; height: .6rem;
    border-radius: 50%; margin-right: .35rem; vertical-align: middle; }}

/* Badges */
.pg-badge {{ display: inline-block; font-size: .72rem; font-weight: 700;
    padding: .12rem .5rem; border-radius: 999px; border: 1px solid; letter-spacing: .03em; }}
.pg-badge.ok {{ color: var(--pg-good); border-color: var(--pg-good); }}
.pg-badge.warn {{ color: var(--pg-warn); border-color: var(--pg-warn); }}
.pg-badge.crit {{ color: var(--pg-crit); border-color: var(--pg-crit); }}
.pg-badge.muted {{ color: var(--pg-muted); border-color: var(--pg-border); }}

/* Verdict banner */
.pg-verdict {{ background: var(--pg-surface); border: 1px solid var(--pg-border);
    border-left: 6px solid var(--pg-verdict-color); border-radius: 12px;
    padding: 1.1rem 1.3rem; margin-bottom: .9rem; }}
.pg-verdict-top {{ display: flex; justify-content: space-between; align-items: baseline;
    flex-wrap: wrap; gap: .5rem; }}
.pg-verdict-label {{ font-size: 1.45rem; font-weight: 700; color: var(--pg-verdict-color); }}
.pg-verdict-score {{ font-size: 1.45rem; font-weight: 700; font-variant-numeric: tabular-nums; }}
.pg-verdict-score small {{ color: var(--pg-muted); font-size: .9rem; font-weight: 500; }}
.pg-verdict-summary {{ color: var(--pg-muted); margin-top: .25rem; font-size: .92rem; }}

/* Risk meter */
.pg-meter {{ position: relative; height: 10px; border-radius: 999px; margin: 1rem 0 1.4rem 0;
    background: linear-gradient(90deg, var(--pg-good) 0%, var(--pg-good) 40%,
        var(--pg-warn) 40%, var(--pg-warn) 70%, var(--pg-crit) 70%, var(--pg-crit) 100%);
    opacity: .9; }}
.pg-meter-marker {{ position: absolute; top: -5px; width: 4px; height: 20px;
    background: #f8fafc; border-radius: 2px; box-shadow: 0 0 0 2px {PAGE_BG}; }}
.pg-meter-scale {{ position: absolute; top: 14px; font-size: .7rem; color: var(--pg-muted);
    transform: translateX(-50%); white-space: nowrap; }}

/* Indicators */
.pg-signal {{ display: flex; gap: .75rem; padding: .7rem 0;
    border-bottom: 1px solid var(--pg-border); }}
.pg-signal:last-child {{ border-bottom: none; }}
.pg-signal-badge {{ flex: 0 0 4.6rem; }}
.pg-signal-title {{ font-weight: 600; font-size: .95rem; }}
.pg-signal-detail {{ color: var(--pg-muted); font-size: .86rem; margin-top: .15rem;
    overflow-wrap: anywhere; }}
.pg-signal-weight {{ margin-left: auto; color: var(--pg-muted); font-size: .8rem;
    white-space: nowrap; font-variant-numeric: tabular-nums; }}

/* Chips */
.pg-chip {{ display: inline-block; background: #17223a; border: 1px solid var(--pg-border);
    border-radius: 6px; padding: .15rem .5rem; margin: 0 .35rem .35rem 0; font-size: .85rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}

.pg-defanged {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9rem;
    background: #17223a; border: 1px solid var(--pg-border); border-radius: 6px;
    padding: .35rem .6rem; overflow-wrap: anywhere; }}

/* Sidebar */
.pg-sidebar-brand {{ font-weight: 700; font-size: 1.15rem; }}
.pg-sidebar-brand span {{ color: var(--pg-accent); }}
.pg-sidebar-foot {{ color: var(--pg-muted); font-size: .75rem; line-height: 1.5; }}
</style>
"""


def apply_theme() -> None:
    """Inject the global stylesheet. Call once per script run."""
    st.markdown(_CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "", eyebrow: str = "") -> None:
    """Render a consistent page title block."""
    eyebrow_html = f'<div class="pg-eyebrow">{html.escape(eyebrow)}</div>' if eyebrow else ""
    sub = f"<p>{html.escape(subtitle)}</p>" if subtitle else ""
    st.markdown(
        f'<div class="pg-header">{eyebrow_html}<h1>{html.escape(title)}</h1>{sub}</div>',
        unsafe_allow_html=True,
    )


ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"


def sidebar_brand() -> None:
    """Logo at the top of the sidebar (above the navigation)."""
    st.logo(
        str(ASSETS_DIR / "logo.svg"),
        size="large",
        icon_image=str(ASSETS_DIR / "icon.svg"),
    )


def sidebar_footer() -> None:
    st.sidebar.markdown(
        f'<div class="pg-sidebar-foot">{APP_TAGLINE}<br>v{APP_VERSION} · Local mode<br>'
        "Submitted links are never opened.<br>Attachments are never executed.<br>"
        "Results are estimates, not certainties.</div>",
        unsafe_allow_html=True,
    )


_SCHEME_RE = re.compile(r"(?i)\bhttp(s?)://")


def defang(text: str) -> str:
    """Make a URL/host non-clickable for display: hxxps://example[.]com."""
    text = _SCHEME_RE.sub(lambda m: f"hxxp{m.group(1)}://", text)
    return text.replace(".", "[.]")
