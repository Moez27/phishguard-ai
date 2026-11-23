"""Tests for user-input validation."""

import pytest

from config.settings import load_settings
from services.validation import (
    ValidationError,
    validate_email_text,
    validate_upload,
    validate_url,
)


@pytest.fixture
def settings(clean_env):
    clean_env.setenv("PHISHGUARD_MAX_EMAIL_CHARS", "1000")
    clean_env.setenv("PHISHGUARD_MAX_UPLOAD_BYTES", "2048")
    clean_env.setenv("PHISHGUARD_MAX_URL_LENGTH", "200")
    return load_settings()


# --- Email text ---


@pytest.mark.parametrize("text", [None, "", "   \n\t "])
def test_empty_email_rejected(settings, text):
    with pytest.raises(ValidationError, match="paste"):
        validate_email_text(text, settings)


def test_too_long_email_rejected(settings):
    with pytest.raises(ValidationError, match="too long"):
        validate_email_text("a" * 1001, settings)


def test_binary_email_rejected(settings):
    with pytest.raises(ValidationError, match="binary"):
        validate_email_text("MZ\x00\x01\x02 payload", settings)


def test_valid_email_is_stripped(settings):
    assert validate_email_text("  Hello there  \n", settings) == "Hello there"


# --- Uploads ---


@pytest.mark.parametrize("name", ["mail.eml", "virus.exe", "doc.pdf", "noext"])
def test_unsupported_upload_extension(settings, name):
    with pytest.raises(ValidationError, match="Unsupported file type"):
        validate_upload(name, b"hello", settings)


def test_upload_checks(settings):
    with pytest.raises(ValidationError, match="No file"):
        validate_upload(None, None, settings)
    with pytest.raises(ValidationError, match="empty"):
        validate_upload("a.txt", b"", settings)
    with pytest.raises(ValidationError, match="too large"):
        validate_upload("a.txt", b"x" * 3000, settings)
    with pytest.raises(ValidationError, match="binary"):
        validate_upload("a.txt", b"abc\x00def", settings)


def test_upload_decodes_utf8_and_cp1252(settings):
    assert validate_upload("A.TXT", "Café ✓".encode(), settings) == "Café ✓"
    assert validate_upload("a.txt", "Café".encode("cp1252"), settings) == "Café"


# --- URLs ---


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/login", "https://example.com/login"),
        ("example.com/a?b=1", "http://example.com/a?b=1"),
        ("http://192.168.0.1:8080/x", "http://192.168.0.1:8080/x"),
        ("  https://xn--pple-43d.com  ", "https://xn--pple-43d.com"),
        ("example.com:8080/login", "http://example.com:8080/login"),
        ("HTTPS://Example.com", "HTTPS://Example.com"),
    ],
)
def test_valid_urls(settings, url, expected):
    assert validate_url(url, settings) == expected


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("", "enter a URL"),
        ("javascript:alert(1)", "Unsupported URL scheme"),
        ("data:text/html,<script>x</script>", "Unsupported URL scheme"),
        ("mailto:someone@example.com", "Unsupported URL scheme"),
        ("ftp://example.com/file", "Unsupported URL scheme"),
        ("file:///etc/passwd", "Unsupported URL scheme"),
        ("http://exa mple.com", "spaces"),
        ("http://example.com:99999/", "not valid"),
        ("http://[::1/", "not valid"),
        ("http://localhost/", "not a complete domain"),
        ("https://", "no domain"),
        ("https://example.com/" + "a" * 300, "too long"),
    ],
)
def test_invalid_urls(settings, url, message):
    with pytest.raises(ValidationError, match=message):
        validate_url(url, settings)
