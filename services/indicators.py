"""Reference lists and weights for the rule-based indicators.

The weights are expert-set heuristics chosen for explainability, inspired by
common phishing-URL features in the literature (IP host, '@' in URL, brand in
subdomain, shorteners, suspicious keywords, ...). They are NOT learned from
data and must be presented as such.
"""

from __future__ import annotations

import re

# --- Brands frequently impersonated (lower-case, compared to domain labels) ---
BRANDS: dict[str, tuple[str, ...]] = {
    # brand keyword -> legitimate registered domains
    "paypal": ("paypal.com", "paypal.me"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"),
    "office365": ("office.com", "microsoft.com", "office365.com"),
    "outlook": ("outlook.com", "live.com", "microsoft.com"),
    "amazon": ("amazon.com", "amazon.fr", "amazon.de", "amazon.co.uk", "amazonaws.com"),
    "netflix": ("netflix.com",),
    "ebay": ("ebay.com", "ebay.fr", "ebay.co.uk", "ebay.de"),
    "google": ("google.com", "gmail.com", "google.fr"),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",),
    "dhl": ("dhl.com", "dhl.fr", "dhl.de"),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
}

URL_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
        "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "bl.ink", "lnkd.in",
    }
)  # fmt: skip

# TLDs over-represented in abuse reports (cheap/free registration). Weak signal only.
SUSPICIOUS_TLDS = frozenset(
    {
        "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
        "work", "rest", "fit", "loan", "kim", "men", "date", "review", "cam", "icu", "sbs",
    }
)  # fmt: skip

URL_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account",
    "update", "confirm", "banking", "password", "webscr", "wallet", "suspend", "unlock",
    "billing", "authenticate", "validation", "recover", "support-ticket",
)  # fmt: skip

DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".hta", ".msi", ".ps1", ".jar", ".lnk", ".iso", ".img", ".html", ".htm", ".svg",
    ".docm", ".xlsm", ".pptm",
)  # fmt: skip

# In a URL path, web-page types (.html, .htm, .svg) are normal: they are only
# dangerous as email ATTACHMENTS (local phishing forms). Downloads stay flagged.
_WEB_PAGE_EXTENSIONS = (".html", ".htm", ".svg")
URL_DOWNLOAD_EXTENSIONS = tuple(e for e in DANGEROUS_EXTENSIONS if e not in _WEB_PAGE_EXTENSIONS)

# --- URL signal weights ------------------------------------------------------
W_IP_HOST = 0.45
W_AT_SYMBOL = 0.35
W_PUNYCODE = 0.35
W_BRAND_MISMATCH = 0.40
W_SHORTENER = 0.25
W_KEYWORD_ONE = 0.15
W_KEYWORD_MANY = 0.25
W_SUSPICIOUS_TLD = 0.20
W_NO_HTTPS = 0.10
W_LONG_URL = 0.10
W_VERY_LONG_URL = 0.15
W_MANY_SUBDOMAINS = 0.20
W_MANY_HYPHENS = 0.15
W_NON_STANDARD_PORT = 0.20
W_EMBEDDED_REDIRECT = 0.20
W_EXECUTABLE_LINK = 0.30
W_DIGIT_HEAVY_HOST = 0.10

LONG_URL = 75
VERY_LONG_URL = 100

# --- Email content patterns (English + French) -------------------------------
_I = re.IGNORECASE

URGENCY_PATTERNS = [
    re.compile(p, _I)
    for p in (
        r"\burgent(ly)?\b",
        r"\bimmediate(ly)?\b",
        r"\bwithin\s+\d+\s*(hours?|hrs?|days?)\b",
        r"\bact\s+now\b",
        r"\bfinal\s+(notice|warning|reminder)\b",
        r"\b(expires?|expiring|expiration)\b",
        r"\blast\s+chance\b",
        r"\bas\s+soon\s+as\s+possible\b",
        r"\bimm[ée]diatement\b",
        r"\bsous\s+\d+\s*(heures?|h|jours?)\b",
        r"\bdernier\s+(avertissement|rappel)\b",
    )
]

CREDENTIAL_PATTERNS = [
    re.compile(p, _I)
    for p in (
        r"\b(verify|confirm|validate|update|re-?enter)\s+(your\s+)?(account|identity|password|"
        r"login|credentials|details|information|payment|billing|card)\b",
        r"\b(enter|provide|submit)\s+(your\s+)?(password|pin|credentials|login|card\s+number|"
        r"security\s+code)\b",
        r"\b(social\s+security|ssn|cvv|cvc|card\s+number|one[- ]time\s+(code|password))\b",
        r"\blog\s*in\s+(details|information|credentials)\b",
        r"\b(v[ée]rifie[rz]?|confirme[rz]?|mettre\s+[àa]\s+jour)\s+(votre|vos)\s+"
        r"(compte|identit[ée]|mot\s+de\s+passe|informations|coordonn[ée]es)\b",
        r"\bmot\s+de\s+passe\b",
    )
]

THREAT_PATTERNS = [
    re.compile(p, _I)
    for p in (
        r"\b(account|access|card)\s+(has\s+been\s+|will\s+be\s+|is\s+)?"
        r"(suspended|locked|closed|disabled|restricted|blocked|terminated)\b",
        r"\bunusual\s+(sign[- ]?in|activity|login)\b",
        r"\bunauthori[sz]ed\s+(access|transaction|activity|login)\b",
        r"\bcompte\s+(sera\s+|a\s+[ée]t[ée]\s+)?(suspendu|bloqu[ée]|ferm[ée]|d[ée]sactiv[ée])\b",
        r"\bactivit[ée]\s+inhabituelle\b",
    )
]

GENERIC_GREETING_PATTERNS = [
    re.compile(p, _I)
    for p in (
        r"\bdear\s+(customer|user|client|member|account\s+holder|valued|sir|madam|beneficiary)\b",
        r"\b(cher|ch[èe]re)\s+(client|cliente|utilisateur|utilisatrice|membre)\b",
    )
]

MONEY_PATTERNS = [
    re.compile(p, _I)
    for p in (
        r"\byou\s+(have\s+)?won\b",
        r"\b(lottery|jackpot|inheritance|beneficiary)\b",
        r"\bwire\s+transfer\b",
        r"\bgift\s+cards?\b",
        r"\b(bitcoin|crypto(currency)?)\s+(payment|wallet|transfer)\b",
        r"\bvous\s+avez\s+gagn[ée]\b",
        r"\bremboursement\b",
    )
]

W_URGENCY = 0.20
W_CREDENTIALS = 0.30
W_THREAT = 0.15
W_GENERIC_GREETING = 0.10
W_MONEY = 0.20
W_LINK_TEXT_MISMATCH = 0.40
W_DANGEROUS_ATTACHMENT = 0.35
W_SENDER_BRAND_SPOOF = 0.30
W_REPLY_TO_MISMATCH = 0.25
