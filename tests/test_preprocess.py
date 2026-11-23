"""Tests for email parsing and text normalisation."""

from ml.preprocess import (
    build_model_text,
    extract_urls,
    html_to_text,
    normalize_text,
    parse_email,
)

MULTIPART = b"""From: a@example.org
Subject: =?utf-8?q?Caf=C3=A9_invoice?=
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="XYZ"

--XYZ
Content-Type: text/plain; charset="utf-8"

Please find the invoice attached.
--XYZ
Content-Type: application/x-msdownload
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA=
--XYZ--
"""


def test_parse_multipart_skips_attachment():
    parsed = parse_email(MULTIPART)
    assert parsed.subject == "Café invoice"  # RFC 2047 encoded-word decoded
    assert "Please find the invoice attached." in parsed.body
    assert parsed.attachment_count == 1
    assert "TVqQ" not in parsed.body  # attachment content never decoded into the body


def test_parse_html_only_email_keeps_link_target():
    raw = (
        "Subject: Verify\nContent-Type: text/html\n\n"
        "<html><head><style>p{}</style></head><body><p>Click "
        '<a href="http://evil.example/login">here</a></p><script>alert(1)</script></body></html>'
    )
    parsed = parse_email(raw)
    assert parsed.has_html
    assert "http://evil.example/login" in parsed.body
    assert "alert" not in parsed.body
    assert "p{}" not in parsed.body


def test_parse_unknown_charset_does_not_crash():
    raw = b"Subject: x\nContent-Type: text/plain; charset=bogus-charset\n\ncaf\xe9"
    parsed = parse_email(raw)
    assert parsed.body.startswith("caf")


def test_parse_garbage_returns_empty_body():
    parsed = parse_email(b"\x00\x01\x02")
    assert parsed.subject == ""


def test_html_to_text_ignores_mailto_and_anchors():
    text = html_to_text('<a href="mailto:x@y.z">mail</a> <a href="#top">top</a>')
    assert "mailto" not in text and "#top" not in text


def test_normalize_replaces_urls_emails_numbers():
    text = normalize_text(
        "Login at HTTPS://Bank.example/a?b=1 or mail admin@bank.com, ref 12,500.00"
    )
    assert "urltoken" in text
    assert "emailtoken" in text
    assert "numtoken" in text
    assert "bank.example" not in text
    assert "admin@bank.com" not in text
    assert text == text.lower()


def test_normalize_empty():
    assert normalize_text("") == ""
    assert normalize_text(None) == ""  # type: ignore[arg-type]


def test_extract_urls_dedup_and_trailing_punctuation():
    urls = extract_urls("Go to http://a.example/x. Then www.b.example, and http://a.example/x")
    assert urls == ["http://a.example/x", "www.b.example"]


def test_build_model_text():
    assert build_model_text("Subj", "Body") == "Subj\nBody"
    assert build_model_text("", "") == ""
