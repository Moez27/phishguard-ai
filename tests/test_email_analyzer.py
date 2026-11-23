"""Tests for email content extraction and rule-based indicators."""

from services.email_analyzer import analyze_email, extract_content, looks_like_raw_email

RAW_SPOOF = """From: "PayPal Service" <service@paypa1-support.com>
Reply-To: help@secure-mail.example
Subject: Your account is limited
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/html

<p>Dear customer, please <a href="http://paypa1-support.com/login">https://www.paypal.com/login</a>
to confirm your account.</p>
--B
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

TVqQAAMAAAAEAAAA
--B--
"""


def codes(analysis):
    return {s.code for s in analysis.signals}


def test_detects_raw_email():
    assert looks_like_raw_email(RAW_SPOOF)
    assert not looks_like_raw_email("Hello Bob,\nSee you tomorrow.")
    assert not looks_like_raw_email("Note: the meeting moved to 3pm.\n\nThanks")


def test_raw_email_extraction():
    c = extract_content(RAW_SPOOF)
    assert c.has_headers and c.has_html
    assert c.subject == "Your account is limited"
    assert "paypa1-support.com" in c.sender
    assert c.attachment_names == ("invoice.pdf.exe",)
    assert "http://paypa1-support.com/login" in c.urls
    assert "TVqQ" not in c.body  # attachment content never decoded


def test_raw_spoof_signals():
    a = analyze_email(RAW_SPOOF)
    assert {
        "email_link_mismatch",
        "attachment_dangerous",
        "content_credentials",
        "sender_brand_spoof",
        "sender_reply_to_mismatch",
        "content_generic_greeting",
    } <= codes(a)
    assert a.rule_score > 0.8


def test_plain_text_with_subject_override():
    c = extract_content("Hi, the report is attached.", subject="Weekly report")
    assert c.subject == "Weekly report"
    assert not c.has_headers and not c.has_html


def test_pasted_html_body_extracts_links():
    html = '<html><body><a href="http://198.51.100.7/x">Click here</a></body></html>'
    c = extract_content(html)
    assert c.has_html
    assert c.urls == ("http://198.51.100.7/x",)
    assert "<a" not in c.body


def test_benign_email_has_no_signals():
    a = analyze_email("Hey Tom, are you free for lunch on Friday? There's a new place nearby.")
    assert a.signals == []
    assert a.rule_score == 0.0


def test_french_phishing_content():
    a = analyze_email(
        "Cher client, votre compte sera suspendu. Veuillez vérifier vos informations immédiatement."
    )
    assert {"content_generic_greeting", "content_threat", "content_credentials",
            "content_urgency"} <= codes(a)  # fmt: skip


def test_suspicious_link_signal_uses_worst_url():
    a = analyze_email("See https://github.com and http://203.0.113.5/bank/login.php")
    link = next(s for s in a.signals if s.code == "email_suspicious_link")
    assert "203.0.113.5" in link.title
    assert len(a.url_analyses) == 2


def test_safe_link_not_reported():
    a = analyze_email("Docs are on https://github.com/org/repo")
    assert "email_suspicious_link" not in codes(a)


def test_matching_link_text_is_not_a_mismatch():
    html = '<a href="https://www.example.com/page">www.example.com</a>'
    assert "email_link_mismatch" not in codes(analyze_email(html))


def test_display_name_with_official_domain_not_spoof():
    raw = 'From: "PayPal" <service@paypal.com>\nSubject: Receipt\n\nThanks for your payment.'
    assert "sender_brand_spoof" not in codes(analyze_email(raw))


def test_link_mismatch_to_ip_and_reply_to_with_unknown_tld():
    raw = (
        'From: "PayPal" <service@paypa1-support.example>\n'
        "Reply-To: help@mailbox-help.example\n"
        "Subject: x\nContent-Type: text/html\n\n"
        '<a href="http://203.0.113.45/update">https://www.paypal.com/account</a>'
    )
    a = analyze_email(raw)
    assert {"email_link_mismatch", "sender_reply_to_mismatch", "sender_brand_spoof"} <= codes(a)
    spoof = next(s for s in a.signals if s.code == "sender_brand_spoof")
    assert "paypa1-support.example" in spoof.detail


def test_html_attachment_is_still_dangerous():
    raw = (
        "From: a@b.example\nSubject: doc\nContent-Type: multipart/mixed; boundary=X\n\n"
        "--X\nContent-Type: text/plain\n\nsee attached\n"
        '--X\nContent-Type: text/html\nContent-Disposition: attachment; filename="login.html"\n\n'
        "<form></form>\n--X--\n"
    )
    assert "attachment_dangerous" in codes(analyze_email(raw))
