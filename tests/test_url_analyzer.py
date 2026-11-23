"""Tests for the offline URL analyser."""

import socket

import pytest

from services.url_analyzer import analyze_url, extract_features


def codes(url):
    return {s.code for s in analyze_url(url).signals}


@pytest.fixture
def no_network(monkeypatch):
    """Make any network access fail loudly."""

    def blocked(*args, **kwargs):
        raise AssertionError("Network access attempted during URL analysis!")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def test_analysis_never_touches_network(no_network):
    for url in (
        "https://www.example.com",
        "http://login.paypal.com.secure.example.xyz/webscr",
        "http://203.0.113.9/x.exe",
    ):
        analyze_url(url)  # would raise if DNS/HTTP were used


def test_benign_url_has_no_signal():
    a = analyze_url("https://github.com/anthropics")
    assert a.signals == []
    assert a.rule_score == 0.0


def test_official_brand_domain_not_flagged():
    assert codes("https://accounts.google.com/ServiceLogin") == set()
    assert codes("https://www.paypal.com/signin") == set()


def test_features_basic():
    f = extract_features("https://a.b.c.shop.example.co.uk:8443/p/q?x=1&y=2")
    assert f.registered_domain == "example.co.uk"
    assert f.subdomain == "a.b.c.shop"
    assert f.num_subdomains == 4
    assert f.port == 8443
    assert f.num_query_params == 2
    assert f.uses_https


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://203.0.113.9/login", "url_ip_host"),
        ("http://3232235777/login", "url_ip_host"),  # decimal-encoded IPv4
        ("https://www.paypal.com@evil.example/", "url_at_symbol"),
        ("https://xn--pple-43d.com/", "url_punycode"),
        ("https://paypal.com.account-check.example/", "url_brand_mismatch"),
        ("https://secure.example/apple/id/login", "url_brand_mismatch"),
        ("https://bit.ly/3xyz", "url_shortener"),
        ("https://shop.example.xyz/", "url_suspicious_tld"),
        ("http://example.com/", "url_no_https"),
        ("https://a.b.c.example.com/", "url_many_subdomains"),
        ("https://my-secure-bank-login.example/", "url_many_hyphens"),
        ("https://example.com:8081/", "url_port"),
        ("https://example.com/r?u=http://evil.example", "url_redirect"),
        ("https://example.com/files/invoice.pdf.exe", "url_executable"),
        ("https://example.com/" + "a" * 120, "url_very_long"),
    ],
)
def test_each_signal(url, expected):
    assert expected in codes(url)


def test_keyword_weight_grows_with_count():
    one = next(
        s for s in analyze_url("https://example.com/login").signals if s.code == "url_keywords"
    )
    many = next(
        s
        for s in analyze_url("https://example.com/login/verify/account").signals
        if s.code == "url_keywords"
    )
    assert many.weight > one.weight


def test_typical_phishing_url_scores_high():
    a = analyze_url("http://paypal.com.secure-login.verify-account.xyz/webscr?cmd=login")
    assert a.rule_score >= 0.7
    assert 0.0 <= a.rule_score <= 1.0


def test_unknown_tld_falls_back_to_last_two_labels():
    f = extract_features("http://login.paypa1-support.example/x")
    assert f.registered_domain == "paypa1-support.example"
    assert f.subdomain == "login"
    assert f.tld == "example"


def test_web_page_extensions_are_not_downloads():
    assert codes("https://docs.python.org/3/library/urllib.parse.html") == set()
    assert "url_executable" not in codes("https://example.com/index.htm")
    assert "url_executable" in codes("https://example.com/setup.msi")
