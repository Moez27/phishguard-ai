"""CSV reports: analysis history, statistics and single results.

Security: every exported cell is protected against CSV/formula injection.
A value such as a domain or indicator detail could start with "=", "+", "-"
or "@" and be executed as a formula by Excel/LibreOffice; such cells are
prefixed with an apostrophe (OWASP recommendation).
Files are UTF-8 with a BOM so that Excel shows accents correctly.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime

import pandas as pd

from database.repository import AnalysisRecord, HistoryStats
from services.risk_engine import AnalysisResult, Verdict
from services.signals import signal_label

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

HISTORY_COLUMNS = [
    "id",
    "created_at_utc",
    "type",
    "verdict",
    "verdict_label",
    "risk_score",
    "rule_score",
    "ml_probability",
    "model_version",
    "target",
    "num_indicators",
    "indicators",
]


def neutralize_cell(value: object) -> object:
    """Prefix text that a spreadsheet would interpret as a formula."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    safe = df.copy()
    # Applied to every column: text may be stored as "object" or pandas' "str"
    # dtype depending on the pandas version; neutralize_cell ignores non-strings.
    for column in safe.columns:
        safe[column] = safe[column].map(neutralize_cell).astype(object)
    safe.columns = [neutralize_cell(c) for c in safe.columns]
    buffer = io.StringIO()
    safe.to_csv(buffer, index=False, lineterminator="\n")
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def history_dataframe(records: list[AnalysisRecord]) -> pd.DataFrame:
    """One row per analysis, with readable indicator names."""
    rows = [
        {
            "id": r.public_id,
            "created_at_utc": r.created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S"),
            "type": r.analysis_type,
            "verdict": r.verdict,
            "verdict_label": Verdict(r.verdict).label,
            "risk_score": round(r.risk_score, 4),
            "rule_score": round(r.rule_score, 4),
            "ml_probability": None if r.ml_probability is None else round(r.ml_probability, 4),
            "model_version": r.model_version or "",
            "target": r.target,
            "num_indicators": len(r.signal_codes),
            "indicators": "; ".join(signal_label(c) for c in r.signal_codes),
        }
        for r in records
    ]
    return pd.DataFrame(rows, columns=HISTORY_COLUMNS)


def history_csv(records: list[AnalysisRecord]) -> bytes:
    return to_csv_bytes(history_dataframe(records))


def stats_csv(stats: HistoryStats, top_indicators: list[tuple[str, int]]) -> bytes:
    """Aggregate statistics as a two-column (metric, value) table."""
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    rows: list[tuple[str, object]] = [
        ("generated_at_utc", generated),
        ("total_analyses", stats.total),
        ("email_analyses", stats.by_type.get("email", 0)),
        ("url_analyses", stats.by_type.get("url", 0)),
    ]
    for verdict, n in stats.by_verdict.items():
        share = n / stats.total if stats.total else 0.0
        rows.append((f"verdict_{verdict}", n))
        rows.append((f"verdict_{verdict}_share", round(share, 4)))
    rows.append(
        ("average_risk_score", "" if stats.average_risk is None else round(stats.average_risk, 4))
    )
    for code, n in top_indicators:
        rows.append((f"indicator: {signal_label(code)}", n))
    return to_csv_bytes(pd.DataFrame(rows, columns=["metric", "value"]))


def result_csv(result: AnalysisResult, record_id: str | None, target: str) -> bytes:
    """A single analysis: summary fields followed by one row per indicator."""
    rows: list[dict] = [
        {"section": "summary", "field": "id", "value": record_id or "not saved"},
        {"section": "summary", "field": "type", "value": result.analysis_type},
        {"section": "summary", "field": "target", "value": target},
        {"section": "summary", "field": "verdict", "value": result.verdict.label},
        {"section": "summary", "field": "risk_score", "value": round(result.risk_score, 4)},
        {"section": "summary", "field": "rule_score", "value": round(result.rule_score, 4)},
        {
            "section": "summary",
            "field": "ml_probability",
            "value": "" if result.ml_probability is None else round(result.ml_probability, 4),
        },
        {"section": "summary", "field": "model_version", "value": result.model_version or ""},
    ]
    rows += [
        {"section": "indicator", "field": s.title, "value": f"+{s.weight:.0%} | {s.detail}"}
        for s in result.signals
    ]
    rows += [{"section": "ai_terms", "field": "term", "value": t} for t in result.ml_terms]
    rows += [
        {"section": "recommendation", "field": str(i + 1), "value": r}
        for i, r in enumerate(result.recommendations)
    ]
    rows.append(
        {
            "section": "disclaimer",
            "field": "limits",
            "value": "Estimate to support a decision, not a certainty. "
            "A low score never guarantees that content is safe.",
        }
    )
    return to_csv_bytes(pd.DataFrame(rows, columns=["section", "field", "value"]))


def export_filename(prefix: str) -> str:
    return f"phishguard_{prefix}_{datetime.now(UTC):%Y%m%d_%H%M%S}.csv"
