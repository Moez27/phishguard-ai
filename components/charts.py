"""Plotly chart builders for the dashboard (pure functions, easy to test).

Conventions (dataviz method): one y-axis per chart, thin marks with 4px rounded
data-ends, 2px surface gap between stacked segments, recessive grid, hover
tooltips on every mark, legend for >= 2 series, text in neutral ink.
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from components.theme import (
    GRID,
    PAGE_BG,
    SERIES_1,
    STATUS_COLORS,
    SURFACE,
    TEXT,
    TEXT_MUTED,
    VERDICT_LABELS,
    verdict_text,
)

VERDICT_ORDER = ("legitimate", "suspect", "phishing")


def _base_layout(fig: go.Figure, height: int = 300) -> go.Figure:
    fig.update_layout(
        height=height,
        margin={"l": 8, "r": 8, "t": 8, "b": 8},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": TEXT, "size": 12},
        hoverlabel={"bgcolor": SURFACE, "bordercolor": GRID, "font": {"color": TEXT}},
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.02,
            "x": 0,
            "font": {"color": TEXT_MUTED},
        },
        bargap=0.25,
    )
    axis = {
        "gridcolor": GRID,
        "linecolor": GRID,
        "zerolinecolor": GRID,
        "tickfont": {"color": TEXT_MUTED},
        "title": {"font": {"color": TEXT_MUTED}},
    }
    fig.update_xaxes(**axis)
    fig.update_yaxes(**axis)
    return fig


def verdict_breakdown(by_verdict: dict[str, int]) -> go.Figure:
    """Horizontal bars, one per verdict, labelled with icon + text + count."""
    total = sum(by_verdict.values()) or 1
    labels = [verdict_text(v) for v in VERDICT_ORDER]
    values = [by_verdict.get(v, 0) for v in VERDICT_ORDER]
    fig = go.Figure(
        go.Bar(
            x=values,
            y=labels,
            orientation="h",
            marker={
                "color": [STATUS_COLORS[v] for v in VERDICT_ORDER],
                "cornerradius": 4,
            },
            text=[f"{n}  ({n / total:.0%})" for n in values],
            textposition="outside",
            textfont={"color": TEXT},
            cliponaxis=False,
            hovertemplate="%{y}: %{x} analyses<extra></extra>",
        )
    )
    _base_layout(fig, height=230)
    fig.update_yaxes(autorange="reversed", showgrid=False)
    fig.update_xaxes(showgrid=True, rangemode="tozero", range=[0, max(values + [1]) * 1.3])
    return fig


def activity_over_time(activity: pd.DataFrame) -> go.Figure:
    """Stacked daily bars by verdict (columns: day, verdict, count)."""
    fig = go.Figure()
    for verdict in VERDICT_ORDER:
        sub = activity[activity["verdict"] == verdict]
        fig.add_trace(
            go.Bar(
                x=pd.to_datetime(sub["day"]),
                y=sub["count"],
                name=verdict_text(verdict),
                marker={
                    "color": STATUS_COLORS[verdict],
                    "line": {"color": PAGE_BG, "width": 2},
                },
                hovertemplate=f"{VERDICT_LABELS[verdict]}: %{{y}}<extra></extra>",
            )
        )
    _base_layout(fig, height=300)
    fig.update_layout(barmode="stack", hovermode="x unified")
    fig.update_yaxes(rangemode="tozero", tickformat=",d", title_text="Analyses")
    fig.update_xaxes(showgrid=False, tickformat="%d %b")
    if not activity.empty:
        days = pd.to_datetime(activity["day"])
        half_day = pd.Timedelta(hours=12)  # keep the first/last bars fully visible
        fig.update_xaxes(range=[days.min() - half_day, days.max() + half_day])
    return fig


def risk_distribution(
    scores: list[tuple[str, float]], suspect: float, phishing: float
) -> go.Figure:
    """Histogram of risk scores with the verdict thresholds marked."""
    values = [s for _, s in scores]
    fig = go.Figure(
        go.Histogram(
            x=values,
            xbins={"start": 0, "end": 1.0001, "size": 0.05},
            marker={"color": SERIES_1, "line": {"color": PAGE_BG, "width": 2}, "cornerradius": 4},
            hovertemplate="Risk %{x}: %{y} analyses<extra></extra>",
            name="Analyses",
        )
    )
    _base_layout(fig, height=300)
    for x, label in ((suspect, "Suspicious ≥"), (phishing, "Likely phishing ≥")):
        fig.add_vline(x=x, line={"color": TEXT_MUTED, "width": 1, "dash": "dot"})
        fig.add_annotation(
            x=x, y=1, yref="paper", text=f"{label} {x:.0%}", showarrow=False,
            xanchor="left", yanchor="top", xshift=4, font={"color": TEXT_MUTED, "size": 11},
        )  # fmt: skip
    fig.update_xaxes(range=[0, 1], tickformat=".0%", title_text="Risk score", showgrid=False)
    fig.update_yaxes(rangemode="tozero", tickformat=",d", title_text="Analyses")
    return fig


def top_indicators(items: list[tuple[str, int]]) -> go.Figure:
    """Horizontal bar of the most frequent indicators (single series)."""
    labels = [label for label, _ in items]
    values = [n for _, n in items]
    fig = go.Figure(
        go.Bar(
            x=values,
            y=labels,
            orientation="h",
            marker={"color": SERIES_1, "cornerradius": 4},
            text=values,
            textposition="outside",
            textfont={"color": TEXT},
            cliponaxis=False,
            hovertemplate="%{y}: seen in %{x} analyses<extra></extra>",
        )
    )
    _base_layout(fig, height=max(220, 36 * len(items) + 40))
    fig.update_yaxes(autorange="reversed", showgrid=False)
    fig.update_xaxes(rangemode="tozero", range=[0, max(values + [1]) * 1.2], tickformat=",d")
    return fig


# Sequential single-hue ramp (dark surface -> series blue) for magnitudes.
SEQUENTIAL = [[0.0, "#16233d"], [1.0, SERIES_1]]


def confusion_heatmap(
    matrix: list[list[int]], rows: list[str], columns: list[str], height: int = 260
) -> go.Figure:
    """Annotated count matrix (rows = true class, columns = predicted)."""
    total_by_row = [max(1, sum(r)) for r in matrix]
    text = [
        [f"{v:,}<br>({v / total_by_row[i]:.1%} of row)" for v in row]
        for i, row in enumerate(matrix)
    ]
    fig = go.Figure(
        go.Heatmap(
            z=matrix,
            x=columns,
            y=rows,
            text=text,
            texttemplate="%{text}",
            textfont={"color": TEXT, "size": 13},
            colorscale=SEQUENTIAL,
            showscale=False,
            xgap=2,
            ygap=2,
            hovertemplate="True: %{y}<br>Predicted: %{x}<br>%{z} emails<extra></extra>",
        )
    )
    _base_layout(fig, height=height)
    fig.update_yaxes(autorange="reversed", showgrid=False, title_text="True class")
    fig.update_xaxes(showgrid=False, side="bottom", title_text="Predicted")
    return fig


def roc_curve_chart(fpr: list[float], tpr: list[float], auc: float) -> go.Figure:
    """ROC curve of the model with the chance diagonal for reference."""
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=[0, 1], y=[0, 1], mode="lines", name="Chance",
            line={"color": TEXT_MUTED, "width": 1, "dash": "dot"}, hoverinfo="skip",
        )
    )  # fmt: skip
    fig.add_trace(
        go.Scatter(
            x=fpr,
            y=tpr,
            mode="lines",
            name=f"Model (AUC {auc:.4f})",
            line={"color": SERIES_1, "width": 2},
            hovertemplate="False-positive rate %{x:.3f}<br>True-positive rate %{y:.3f}"
            "<extra></extra>",
        )
    )
    _base_layout(fig, height=300)
    fig.update_xaxes(range=[0, 1], tickformat=".0%", title_text="False-positive rate")
    fig.update_yaxes(range=[0, 1.02], tickformat=".0%", title_text="True-positive rate")
    return fig
