"""Synthetic examples for demonstrations and quick manual tests.

All examples were written for PhishGuard. Every domain uses the reserved
``.example`` TLD or the 203.0.113.0/24 documentation range (RFC 2606 / RFC 5737),
so no example can ever point to a real site.
"""

from __future__ import annotations

EMAIL_EXAMPLES: dict[str, tuple[str, str]] = {
    "Credential phishing (synthetic)": (
        "Action required: unusual sign-in detected",
        "Dear customer,\n\nWe detected an unusual sign-in to your account from a new device. "
        "For your security, your account will be suspended within 24 hours unless you verify "
        "your identity.\n\nVerify your account now: "
        "http://secure-login.account-verify.example/signin?session=8842\n\n"
        "Thank you,\nThe Security Team",
    ),
    "Spoofed sender + attachment (raw email, synthetic)": (
        "",
        'From: "PayPal Service" <service@paypa1-support.example>\n'
        "Reply-To: billing-dept@mailbox-help.example\n"
        "Subject: Your account access has been limited\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="SEP"\n\n'
        "--SEP\n"
        "Content-Type: text/html; charset=utf-8\n\n"
        "<html><body><p>Dear customer,</p><p>We noticed unauthorized activity. Please "
        '<a href="http://203.0.113.45/paypal/update">https://www.paypal.com/account</a> '
        "to confirm your billing information immediately.</p></body></html>\n"
        "--SEP\n"
        "Content-Type: application/octet-stream\n"
        'Content-Disposition: attachment; filename="statement.pdf.exe"\n\n'
        "UEhJU0hHVUFSRCBERU1PIC0gTk9UIEEgUkVBTCBGSUxF\n"
        "--SEP--\n",
    ),
    "Legitimate: colleague message (synthetic)": (
        "Slides for Thursday's review",
        "Hi Sam,\n\nI've updated the slides for Thursday's project review with the new test "
        "results. Could you check the timeline on page 4 before the meeting? Happy to go "
        "through it together tomorrow morning if that's easier.\n\nThanks,\nNadia",
    ),
    "Legitimate: delivery notice (synthetic)": (
        "Your parcel is on its way",
        "Hello Nadia,\n\nYour order of two notebooks left our warehouse this morning and should "
        "arrive on Friday. You can follow the delivery from the Orders section of the shop "
        "website.\n\nThanks for your purchase,\nThe Paper Shop team",
    ),
}

URL_EXAMPLES: dict[str, str] = {
    "Brand on look-alike domain (synthetic)": (
        "http://paypal.com.secure-login.account-verify.xyz/webscr?cmd=_login"
    ),
    "Raw IP address + executable (synthetic)": "http://203.0.113.7:8080/invoice/statement.pdf.exe",
    "Credential page with '@' trick (synthetic)": (
        "https://www.bank.example@login-verify.example/secure/update"
    ),
    "Ordinary documentation page": "https://docs.python.org/3/library/urllib.parse.html",
}
