"""Explainable risk signals shared by the email and URL analysers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class Category(StrEnum):
    URL = "url"
    CONTENT = "content"
    SENDER = "sender"
    ATTACHMENT = "attachment"


@dataclass(frozen=True)
class Signal:
    """One observable indicator that contributed to the risk score.

    ``weight`` is the indicator's stand-alone risk contribution in [0, 1]. Weights
    are expert-set heuristics (documented in services/indicators.py), not
    learned probabilities.
    """

    code: str
    category: Category
    title: str
    detail: str
    weight: float

    @property
    def severity(self) -> str:
        if self.weight >= 0.35:
            return "high"
        if self.weight >= 0.2:
            return "medium"
        return "low"


# Generic, static label for every indicator code (used in history/dashboard charts).
SIGNAL_LABELS: dict[str, str] = {
    "url_ip_host": "IP address instead of domain",
    "url_at_symbol": "'@' in URL",
    "url_punycode": "Look-alike domain",
    "url_brand_mismatch": "Brand on unrelated domain",
    "url_shortener": "URL shortener",
    "url_keywords": "Sensitive keywords in URL",
    "url_suspicious_tld": "Often-abused TLD",
    "url_no_https": "No HTTPS",
    "url_long": "Long URL",
    "url_very_long": "Very long URL",
    "url_many_subdomains": "Many subdomains",
    "url_many_hyphens": "Many hyphens in domain",
    "url_port": "Non-standard port",
    "url_redirect": "Embedded redirection",
    "url_executable": "Link to dangerous file",
    "url_digits": "Many digits in domain",
    "content_credentials": "Credential request",
    "content_urgency": "Urgency",
    "content_threat": "Suspension threat",
    "content_money": "Money / prize lure",
    "content_generic_greeting": "Generic greeting",
    "email_suspicious_link": "Suspicious link",
    "email_link_mismatch": "Misleading link text",
    "attachment_dangerous": "Dangerous attachment",
    "sender_brand_spoof": "Sender impersonates brand",
    "sender_reply_to_mismatch": "Reply-To mismatch",
}


def signal_label(code: str) -> str:
    return SIGNAL_LABELS.get(code, code.replace("_", " ").capitalize())


def combine_weights(weights: Iterable[float]) -> float:
    """Noisy-OR combination: 1 - prod(1 - w).

    Several weak indicators add up, but the result never exceeds 1, and one
    indicator alone never scores more than its own weight.
    """
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - min(max(w, 0.0), 1.0)
    return 1.0 - remaining
