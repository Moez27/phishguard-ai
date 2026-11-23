"""Security regression tests: denial-of-service inputs, message echo, demo examples."""

import time

import pytest

from config.settings import load_settings
from ml.preprocess import normalize_text
from services.analysis import run_email_analysis, run_url_analysis
from services.email_analyzer import analyze_email
from services.examples import EMAIL_EXAMPLES, URL_EXAMPLES
from services.risk_engine import Verdict
from services.validation import ValidationError, _safe_echo, validate_url

# Inputs that used to (or could) trigger catastrophic regex backtracking.
ADVERSARIAL = {
    "dotted": "a." * 25_000,
    "hyphenated": "a-" * 25_000,
    "dotted_then_at": "a." * 24_990 + " @x.example",
    "many_at": "a@" * 25_000,
    "no_spaces": "x" * 50_000,
    "repeated_phrases": "verify your account within 24 hours " * 1_300,
}


@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_no_catastrophic_backtracking(name):
    text = ADVERSARIAL[name]
    start = time.perf_counter()
    normalize_text(text)
    analyze_email(text)
    elapsed = time.perf_counter() - start
    # Was ~14 s for "dotted" before the EMAIL_RE fix; linear now (~0.1 s).
    assert elapsed < 3.0, f"{name} took {elapsed:.1f}s"


def test_email_regex_still_matches_normal_addresses():
    out = normalize_text("Write to admin@bank.example or first.last-1@mail.co.uk today")
    assert out.count("emailtoken") == 2


def test_safe_echo_strips_markup():
    assert (
        _safe_echo("**bold** [x](javascript:alert(1)) <b>")
        == "??bold?? ?x??javascript:alert?1?? ?b?"
    )
    assert len(_safe_echo("a" * 500)) == 80


def test_url_error_messages_do_not_echo_markup(clean_env):
    settings = load_settings()
    with pytest.raises(ValidationError) as exc:
        validate_url("http://abc[x](y)/", settings)
    assert "[" not in str(exc.value).split("valid:", 1)[-1]
    with pytest.raises(ValidationError) as exc:
        validate_url("http://ex*ample/", settings)
    assert "*" not in str(exc.value)


# --- Demo scenarios stay stable (rules only, no trained model needed) -----------


@pytest.mark.parametrize("name", list(URL_EXAMPLES))
def test_url_examples_verdicts(clean_env, name):
    expected = {
        "Brand on look-alike domain (synthetic)": Verdict.PHISHING,
        "Raw IP address + executable (synthetic)": Verdict.PHISHING,
        "Credential page with '@' trick (synthetic)": Verdict.SUSPECT,
        "Ordinary documentation page": Verdict.LEGITIMATE,
    }[name]
    assert run_url_analysis(URL_EXAMPLES[name], load_settings()).verdict is expected


@pytest.mark.parametrize("name", list(EMAIL_EXAMPLES))
def test_email_examples_rule_evidence(clean_env, name):
    subject, text = EMAIL_EXAMPLES[name]
    result = run_email_analysis(text, load_settings(), None, subject=subject)
    if name.startswith("Legitimate"):
        assert result.signals == []
        assert result.verdict is Verdict.LEGITIMATE
    else:
        assert result.rule_score >= 0.7
        assert result.verdict is Verdict.PHISHING


def test_example_domains_are_reserved():
    """Examples must never point to a real third-party site."""
    import re

    hosts = re.findall(r"https?://([^/\s\"<>]+)", " ".join(t for _, t in EMAIL_EXAMPLES.values()))
    hosts += [re.sub(r"^https?://", "", u).split("/")[0] for u in URL_EXAMPLES.values()]
    for host in hosts:
        host = host.split("@")[-1].split(":")[0]
        assert (
            host.endswith(".example")
            or host.startswith("203.0.113.")
            or host == "www.paypal.com"  # shown as misleading link TEXT, real href is 203.0.113.x
            or host == "docs.python.org"  # harmless documentation page
            or host.endswith(".xyz")
            and "account-verify" in host  # look-alike, never opened
        ), host
