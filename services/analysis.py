"""Facade used by the interface: validate -> analyse -> score -> result.

The UI only calls these functions; it holds no business logic.
"""

from __future__ import annotations

import logging
import time

from config.settings import Settings
from ml.predict import ModelNotAvailableError, PhishingClassifier
from services.email_analyzer import analyze_email
from services.risk_engine import (
    AnalysisResult,
    combine_email_score,
    readable_terms,
    recommendations,
    verdict_for,
)
from services.url_analyzer import analyze_url
from services.validation import validate_email_text, validate_url

logger = logging.getLogger(__name__)

MODEL_UNAVAILABLE_WARNING = (
    "The AI model is not available, so this result is based on rule-based indicators only. "
    "Train it with: python -m scripts.prepare_data, then python -m ml.train"
)
URL_SCOPE_NOTE = (
    "Offline analysis of the address only: the link was not opened and no external "
    "reputation service was queried."
)


def load_classifier(settings: Settings) -> tuple[PhishingClassifier | None, str | None]:
    """Load the trained model, or return ``(None, reason)`` if it cannot be used."""
    try:
        return PhishingClassifier.load(settings.model_path, settings.model_metadata_path), None
    except ModelNotAvailableError as exc:
        logger.warning("Model unavailable: %s", exc)
        return None, str(exc)
    except Exception:  # corrupted pickle, version mismatch, ...
        logger.exception("Model could not be loaded")
        return None, "The model file could not be loaded. Retrain it with: python -m ml.train"


def run_email_analysis(
    text: str | None,
    settings: Settings,
    classifier: PhishingClassifier | None,
    subject: str = "",
) -> AnalysisResult:
    """Analyse an email. Raises ``ValidationError`` for invalid input."""
    start = time.perf_counter()
    text = validate_email_text(text, settings)
    analysis = analyze_email(text, subject=subject or "")
    content = analysis.content

    warnings: list[str] = []
    ml_probability = None
    ml_terms: list[str] = []
    if classifier is None:
        warnings.append(MODEL_UNAVAILABLE_WARNING)
    else:
        try:
            ml_probability = classifier.predict(content.subject, content.body).probability
            ml_terms = readable_terms(classifier.explain(content.subject, content.body, top_n=8))
        except Exception:  # never crash the page because of the model
            logger.exception("Model prediction failed")
            warnings.append("The AI model failed on this input; rule-based result only.")
    if not content.body and not content.subject:
        warnings.append("No readable text was found in this email.")

    rule_score = analysis.rule_score
    score = combine_email_score(ml_probability, rule_score, settings.ml_weight)
    verdict = verdict_for(score, settings)
    sender_domain = content.sender.rsplit("@", 1)[-1].strip("> ").lower() if content.sender else ""
    return AnalysisResult(
        analysis_type="email",
        verdict=verdict,
        risk_score=score,
        rule_score=rule_score,
        ml_probability=ml_probability,
        signals=sorted(analysis.signals, key=lambda s: s.weight, reverse=True),
        ml_terms=ml_terms,
        recommendations=recommendations(verdict, analysis.signals, "email"),
        warnings=warnings,
        model_version=classifier.version if classifier else None,
        model_algorithm=classifier.algorithm if classifier else None,
        metadata={
            "num_urls": len(content.urls),
            "num_attachments": len(content.attachment_names),
            "has_html": content.has_html,
            "has_headers": content.has_headers,
            "sender_domain": sender_domain,
            "text_length": len(text),
        },
        duration_ms=(time.perf_counter() - start) * 1000,
    )


def run_url_analysis(url: str | None, settings: Settings) -> AnalysisResult:
    """Analyse a URL offline. Raises ``ValidationError`` for invalid input."""
    start = time.perf_counter()
    url = validate_url(url, settings)
    analysis = analyze_url(url)
    score = analysis.rule_score
    verdict = verdict_for(score, settings)
    f = analysis.features
    return AnalysisResult(
        analysis_type="url",
        verdict=verdict,
        risk_score=score,
        rule_score=score,
        ml_probability=None,
        signals=sorted(analysis.signals, key=lambda s: s.weight, reverse=True),
        recommendations=recommendations(verdict, analysis.signals, "url"),
        warnings=[URL_SCOPE_NOTE],
        metadata={
            "host": f.host,
            "registered_domain": f.registered_domain,
            "scheme": f.scheme,
            "length": f.length,
            "num_subdomains": f.num_subdomains,
            "uses_https": f.uses_https,
            "has_ip_host": f.has_ip_host,
        },
        duration_ms=(time.perf_counter() - start) * 1000,
    )
