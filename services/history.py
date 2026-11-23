"""Record analyses in the local history (minimal data, privacy by default)."""

from __future__ import annotations

import logging

from config.settings import Settings
from database.repository import insert_analysis
from services.risk_engine import AnalysisResult

logger = logging.getLogger(__name__)


def history_target(result: AnalysisResult) -> str:
    """Short, non-sensitive label: URL host or email sender domain."""
    if result.analysis_type == "url":
        return str(result.metadata.get("host", ""))
    return str(result.metadata.get("sender_domain", ""))


def record_analysis(
    result: AnalysisResult, settings: Settings, raw_text: str | None = None
) -> str | None:
    """Save ``result`` and return its id, or ``None`` if saving failed.

    The analysed text is stored only for emails and only when
    ``settings.store_email_body`` is enabled. A storage failure never breaks
    the analysis: it is logged (without content) and reported as ``None``.
    """
    content = raw_text if (settings.store_email_body and result.analysis_type == "email") else None
    try:
        return insert_analysis(
            settings.db_path,
            analysis_type=result.analysis_type,
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            rule_score=result.rule_score,
            ml_probability=result.ml_probability,
            model_version=result.model_version,
            target=history_target(result),
            signal_codes=[s.code for s in result.signals],
            metadata=result.metadata,
            duration_ms=result.duration_ms,
            content=content,
        )
    except Exception:
        logger.exception("Could not save the analysis to the history database")
        return None
