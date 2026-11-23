"""Tests for score combination, verdicts, recommendations and the analysis facade."""

from dataclasses import dataclass

import pytest

from config.settings import load_settings
from services.analysis import (
    MODEL_UNAVAILABLE_WARNING,
    load_classifier,
    run_email_analysis,
    run_url_analysis,
)
from services.risk_engine import (
    Verdict,
    combine_email_score,
    readable_terms,
    recommendations,
    verdict_for,
)
from services.signals import Category, Signal, combine_weights
from services.validation import ValidationError


@pytest.fixture
def settings(clean_env, tmp_path):
    clean_env.setenv("PHISHGUARD_MODELS_DIR", str(tmp_path / "models"))
    return load_settings()


@dataclass
class _Pred:
    probability: float


class FakeClassifier:
    """Deterministic stand-in for PhishingClassifier."""

    version = "test-1"
    algorithm = "fake"

    def __init__(self, probability=0.5, fail=False):
        self.probability, self.fail = probability, fail

    def predict(self, subject, body):
        if self.fail:
            raise RuntimeError("boom")
        return _Pred(self.probability)

    def explain(self, subject, body, top_n=8):
        return [("verify urltoken", 0.3), ("account", 0.2)]


# --- Pure functions ---


def test_combine_weights_noisy_or():
    assert combine_weights([]) == 0.0
    assert combine_weights([0.5]) == 0.5
    assert combine_weights([0.5, 0.5]) == pytest.approx(0.75)
    assert combine_weights([1.5, -1]) == 1.0  # clamped


def test_ml_alone_cannot_reach_phishing(settings):
    score = combine_email_score(1.0, 0.0, settings.ml_weight)
    assert verdict_for(score, settings) is Verdict.SUSPECT


def test_strong_rules_alone_reach_phishing(settings):
    score = combine_email_score(0.0, 0.85, settings.ml_weight)
    assert verdict_for(score, settings) is Verdict.PHISHING


def test_no_model_uses_rules_only():
    assert combine_email_score(None, 0.42, 0.5) == 0.42


@pytest.mark.parametrize(
    ("score", "verdict"),
    [(0.0, Verdict.LEGITIMATE), (0.39, Verdict.LEGITIMATE), (0.4, Verdict.SUSPECT),
     (0.69, Verdict.SUSPECT), (0.7, Verdict.PHISHING), (1.0, Verdict.PHISHING)],
)  # fmt: skip
def test_verdict_thresholds(settings, score, verdict):
    assert verdict_for(score, settings) is verdict


def test_verdict_label_and_icon_not_colour_only():
    assert Verdict.PHISHING.label == "Likely phishing"
    assert {v.icon for v in Verdict} == {"✔", "⚠", "✖"}


def test_readable_terms_maps_placeholders():
    assert readable_terms([("verify urltoken", 1), ("numtoken", 1), ("verify urltoken", 1)]) == [
        "verify [link]",
        "[number]",
    ]


def test_recommendations_never_promise_safety():
    advice = recommendations(Verdict.LEGITIMATE, [], "email")
    assert any("does not guarantee" in a for a in advice)


def test_recommendations_follow_signals():
    sig = Signal("content_credentials", Category.CONTENT, "t", "d", 0.3)
    advice = " ".join(recommendations(Verdict.PHISHING, [sig], "email"))
    assert "do not ask for passwords" in advice


# --- Facade ---


def test_email_analysis_with_model(settings):
    r = run_email_analysis(
        "Dear customer, verify your password immediately at http://203.0.113.9/login",
        settings,
        FakeClassifier(0.9),
        subject="Urgent",
    )
    assert r.analysis_type == "email"
    assert r.verdict is Verdict.PHISHING
    assert r.ml_probability == 0.9
    assert r.ml_terms == ["verify [link]", "account"]
    assert r.model_version == "test-1"
    assert r.signals == sorted(r.signals, key=lambda s: s.weight, reverse=True)
    assert "body" not in r.metadata and r.metadata["num_urls"] == 1
    assert r.duration_ms >= 0


def test_email_analysis_without_model_warns(settings):
    r = run_email_analysis("Lunch on Friday?", settings, None)
    assert MODEL_UNAVAILABLE_WARNING in r.warnings
    assert r.ml_probability is None
    assert r.verdict is Verdict.LEGITIMATE


def test_model_failure_does_not_crash(settings):
    r = run_email_analysis("Hello", settings, FakeClassifier(fail=True))
    assert r.ml_probability is None
    assert any("failed" in w for w in r.warnings)


def test_invalid_inputs_raise_validation_error(settings):
    with pytest.raises(ValidationError):
        run_email_analysis("   ", settings, None)
    with pytest.raises(ValidationError):
        run_url_analysis("javascript:alert(1)", settings)


def test_url_analysis_states_scope(settings):
    r = run_url_analysis("http://paypal.com.secure-login.verify-account.xyz/webscr", settings)
    assert r.analysis_type == "url"
    assert r.verdict is Verdict.PHISHING
    assert r.ml_probability is None
    assert any("not opened" in w and "reputation" in w for w in r.warnings)
    assert r.metadata["registered_domain"] == "verify-account.xyz"


def test_load_classifier_missing_model(settings):
    clf, reason = load_classifier(settings)
    assert clf is None
    assert "No trained model" in reason
