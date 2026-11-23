"""Combine ML and rule-based evidence into a risk score, verdict and advice.

Scoring policy (documented for the report)
------------------------------------------
* URL analysis:   risk = rule score (no URL model is trained in this project).
* Email analysis: risk = max(w * p_ml + (1 - w) * rules,  RULE_FLOOR * rules)
  where ``p_ml`` is the model's phishing probability and ``w`` = settings.ml_weight.

Consequences (intentional, see data/README.md "Known limits"):
* With w = 0.5, the ML model alone can bring an email to *Suspect* at most;
  reaching *Phishing* requires concrete, explainable indicators as well.
  This compensates the model's known false positives on modern legitimate
  transactional emails.
* Strong indicators alone (e.g. credential request + IP link) can reach
  *Phishing* even if the model disagrees.
* If the model is unavailable, the score is the rule score and a warning is shown.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from config.settings import Settings
from services.signals import Category, Signal

RULE_FLOOR = 0.9

PLACEHOLDER_LABELS = {"urltoken": "[link]", "emailtoken": "[email address]", "numtoken": "[number]"}


class Verdict(StrEnum):
    LEGITIMATE = "legitimate"
    SUSPECT = "suspect"
    PHISHING = "phishing"

    @property
    def label(self) -> str:
        """Cautious wording: a verdict is an estimate, never a certainty."""
        return {
            Verdict.LEGITIMATE: "Likely legitimate",
            Verdict.SUSPECT: "Suspicious",
            Verdict.PHISHING: "Likely phishing",
        }[self]

    @property
    def icon(self) -> str:
        """Text symbol so the verdict is never conveyed by colour alone."""
        return {Verdict.LEGITIMATE: "✔", Verdict.SUSPECT: "⚠", Verdict.PHISHING: "✖"}[self]


@dataclass(frozen=True)
class AnalysisResult:
    """Everything the interface needs to display (and later store) an analysis."""

    analysis_type: str  # "email" or "url"
    verdict: Verdict
    risk_score: float
    rule_score: float
    ml_probability: float | None
    signals: list[Signal]
    ml_terms: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    model_version: str | None = None
    model_algorithm: str | None = None
    metadata: dict = field(default_factory=dict)  # minimal, no email body
    duration_ms: float = 0.0

    @property
    def summary(self) -> str:
        parts = [f"Risk {self.risk_score:.0%} — {self.verdict.label}."]
        n = len(self.signals)
        parts.append(f"{n} indicator{'s' if n != 1 else ''} found.")
        if self.ml_probability is not None:
            parts.append(f"Model phishing probability: {self.ml_probability:.0%}.")
        return " ".join(parts)


def combine_email_score(ml_probability: float | None, rule_score: float, ml_weight: float) -> float:
    if ml_probability is None:
        return rule_score
    blended = ml_weight * ml_probability + (1.0 - ml_weight) * rule_score
    return min(1.0, max(blended, RULE_FLOOR * rule_score))


def verdict_for(score: float, settings: Settings) -> Verdict:
    if score >= settings.phishing_threshold:
        return Verdict.PHISHING
    if score >= settings.suspect_threshold:
        return Verdict.SUSPECT
    return Verdict.LEGITIMATE


def readable_terms(terms: list[tuple[str, float]]) -> list[str]:
    """Turn model n-grams into readable text (placeholders -> [link], ...)."""
    out: list[str] = []
    for term, _ in terms:
        words = [PLACEHOLDER_LABELS.get(w, w) for w in term.split()]
        text = " ".join(words)
        if text not in out:
            out.append(text)
    return out


def recommendations(verdict: Verdict, signals: list[Signal], analysis_type: str) -> list[str]:
    codes = {s.code for s in signals}
    categories = {s.category for s in signals}
    advice: list[str] = []
    if verdict is Verdict.PHISHING:
        advice.append(
            "Do not click any link, do not reply and do not open attachments."
            if analysis_type == "email"
            else "Do not visit this address and do not enter any information on it."
        )
        advice.append("Report it to your IT/security team (or your provider's abuse service).")
    elif verdict is Verdict.SUSPECT:
        advice.append("Be cautious: verify the request through an official channel you already "
                      "know (official website typed by hand, known phone number).")  # fmt: skip
    else:
        advice.append("No strong indicator was found, but this does not guarantee the "
                      "message or link is safe. Stay vigilant.")  # fmt: skip
    if "content_credentials" in codes:
        advice.append("Legitimate organisations do not ask for passwords or codes by email.")
    if Category.URL in categories and verdict is not Verdict.LEGITIMATE:
        advice.append("Hover over links to check the real destination before any click; "
                      "prefer typing the official address yourself.")  # fmt: skip
    if "attachment_dangerous" in codes:
        advice.append("Never open executable, script or HTML attachments from unexpected emails.")
    if Category.SENDER in categories:
        advice.append("Check the real sender address, not only the display name.")
    return advice
