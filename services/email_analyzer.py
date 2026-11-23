"""Email content extraction and rule-based indicators.

SECURITY: links are only parsed as text (never opened) and attachments are only
identified by their declared file name (never decoded, saved or executed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr

from ml.preprocess import extract_html_links, extract_urls, html_to_text, parse_email
from services import indicators as ind
from services.signals import Category, Signal, combine_weights
from services.url_analyzer import OFFICIAL_DOMAINS, UrlAnalysis, analyze_url, extract_features

MAX_URLS_ANALYSED = 50
# Minimum URL rule score for a link to be reported as suspicious in an email
LINK_REPORT_THRESHOLD = 0.20

_HEADER_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,40}:\s?.*$")
_KNOWN_HEADERS = re.compile(
    r"(?im)^(from|to|subject|date|received|return-path|reply-to|message-id|mime-version|"
    r"content-type|delivered-to|cc):"
)
_HTML_HINT = re.compile(r"(?i)<(html|body|a\s+[^>]*href|div|table|p)\b")
_DOMAIN_LIKE = re.compile(r"(?i)^(https?://)?(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(/\S*)?$")


@dataclass(frozen=True)
class EmailContent:
    subject: str
    body: str
    sender: str
    reply_to: str
    urls: tuple[str, ...]
    html_links: tuple[tuple[str, str], ...]
    attachment_names: tuple[str, ...]
    has_html: bool
    has_headers: bool


@dataclass(frozen=True)
class EmailAnalysis:
    content: EmailContent
    signals: list[Signal] = field(default_factory=list)
    url_analyses: list[UrlAnalysis] = field(default_factory=list)

    @property
    def rule_score(self) -> float:
        return combine_weights(s.weight for s in self.signals)


# --- Extraction -------------------------------------------------------------


def looks_like_raw_email(text: str) -> bool:
    """True if the text starts with an RFC 822 header block (e.g. 'From: ...')."""
    first = next((line for line in text.splitlines() if line.strip()), "")
    if not _HEADER_LINE.match(first):
        return False
    head = text.split("\n\n", 1)[0]
    return len(_KNOWN_HEADERS.findall(head)) >= 1


def extract_content(text: str, subject: str = "") -> EmailContent:
    """Extract subject, body, sender, links and attachment names from user input."""
    if looks_like_raw_email(text):
        parsed = parse_email(text)
        body, links = parsed.body, parsed.html_links
        subj = parsed.subject or subject
        sender, reply_to = parsed.sender, parsed.reply_to
        attachments, has_html, has_headers = parsed.attachment_names, parsed.has_html, True
    else:
        has_html = bool(_HTML_HINT.search(text))
        links = tuple(extract_html_links(text)) if has_html else ()
        body = html_to_text(text) if has_html else text
        subj, sender, reply_to, attachments, has_headers = subject, "", "", (), False

    urls: dict[str, None] = {}
    for href in [h for _, h in links] + extract_urls(body):
        if href.lower().startswith(("http://", "https://", "www.")):
            urls.setdefault(href, None)
    return EmailContent(
        subject=subj.strip(),
        body=body.strip(),
        sender=sender,
        reply_to=reply_to,
        urls=tuple(list(urls)[:MAX_URLS_ANALYSED]),
        html_links=tuple(links),
        attachment_names=tuple(attachments),
        has_html=has_html,
        has_headers=has_headers,
    )


# --- Signals -----------------------------------------------------------------


def _matches(patterns: list[re.Pattern[str]], text: str, limit: int = 3) -> list[str]:
    found: dict[str, None] = {}
    for pattern in patterns:
        for match in pattern.finditer(text):
            found.setdefault(" ".join(match.group(0).split()).lower(), None)
            if len(found) >= limit:
                return list(found)
    return list(found)


def _quote(items: list[str]) -> str:
    return ", ".join(f"“{i}”" for i in items)


def _content_signals(text: str) -> list[Signal]:
    rules = [
        ("content_credentials", "Request for credentials or personal data",
         ind.CREDENTIAL_PATTERNS, ind.W_CREDENTIALS),
        ("content_urgency", "Urgent or time-pressure language",
         ind.URGENCY_PATTERNS, ind.W_URGENCY),
        ("content_threat", "Threat of account suspension or security alert",
         ind.THREAT_PATTERNS, ind.W_THREAT),
        ("content_money", "Money, prize or payment lure", ind.MONEY_PATTERNS, ind.W_MONEY),
        ("content_generic_greeting", "Generic greeting",
         ind.GENERIC_GREETING_PATTERNS, ind.W_GENERIC_GREETING),
    ]  # fmt: skip
    signals = []
    for code, title, patterns, weight in rules:
        found = _matches(patterns, text)
        if found:
            signals.append(
                Signal(code, Category.CONTENT, title, f"Found: {_quote(found)}.", weight)
            )
    return signals


def _registered(url_or_domain: str) -> str:
    """Registered domain, or the raw host for an IP address ("" if unparsable)."""
    try:
        features = extract_features(url_or_domain)
    except ValueError:
        return ""
    return features.registered_domain or features.host


def _link_mismatch_signals(links: tuple[tuple[str, str], ...]) -> list[Signal]:
    """Visible link text shows one domain while the real target is another."""
    mismatches = []
    for text, href in links:
        if not _DOMAIN_LIKE.match(text) or not href.lower().startswith(("http", "www.")):
            continue
        shown, real = _registered(text), _registered(href)
        if shown and real and shown != real:
            mismatches.append(f"shows “{shown}” but leads to “{real}”")
    if not mismatches:
        return []
    detail = "A link " + "; ".join(mismatches[:3]) + "."
    return [
        Signal(
            "email_link_mismatch",
            Category.URL,
            "Link text does not match its real destination",
            detail,
            ind.W_LINK_TEXT_MISMATCH,
        )
    ]


def _attachment_signals(names: tuple[str, ...]) -> list[Signal]:
    risky = [n for n in names if n.lower().endswith(ind.DANGEROUS_EXTENSIONS)]
    if not risky:
        return []
    return [
        Signal(
            "attachment_dangerous",
            Category.ATTACHMENT,
            "Potentially dangerous attachment type",
            f"Attachment(s): {_quote(risky[:3])}. Not opened by PhishGuard - do not open it.",
            ind.W_DANGEROUS_ATTACHMENT,
        )
    ]


def _domain_of(address: str) -> str:
    _, addr = parseaddr(address)
    return _registered(addr.rsplit("@", 1)[-1]) if "@" in addr else ""


def _sender_signals(sender: str, reply_to: str) -> list[Signal]:
    signals: list[Signal] = []
    if not sender:
        return signals
    display, _ = parseaddr(sender)
    sender_domain = _domain_of(sender)
    claimed = [b for b in ind.BRANDS if b in display.lower().replace(" ", "")]
    if claimed and sender_domain and sender_domain not in OFFICIAL_DOMAINS:
        signals.append(
            Signal(
                "sender_brand_spoof",
                Category.SENDER,
                "Sender name impersonates a brand",
                f"The sender calls itself “{display}” but writes from “{sender_domain}”.",
                ind.W_SENDER_BRAND_SPOOF,
            )
        )
    reply_domain = _domain_of(reply_to)
    if reply_domain and sender_domain and reply_domain != sender_domain:
        signals.append(
            Signal(
                "sender_reply_to_mismatch",
                Category.SENDER,
                "Replies go to a different domain",
                f"Sent from “{sender_domain}” but replies are directed to “{reply_domain}”.",
                ind.W_REPLY_TO_MISMATCH,
            )
        )
    return signals


def _link_signal(url_analyses: list[UrlAnalysis]) -> list[Signal]:
    if not url_analyses:
        return []
    worst = max(url_analyses, key=lambda a: a.rule_score)
    if worst.rule_score < LINK_REPORT_THRESHOLD:
        return []
    reasons = ", ".join(s.title.lower() for s in worst.signals[:3])
    return [
        Signal(
            "email_suspicious_link",
            Category.URL,
            f"Suspicious link to {worst.features.host}",
            f"Link risk {worst.rule_score:.0%}: {reasons}. The link was not opened.",
            worst.rule_score,
        )
    ]


def analyze_email(text: str, subject: str = "") -> EmailAnalysis:
    """Extract content and compute rule-based indicators for an email."""
    content = extract_content(text, subject)
    url_analyses = []
    for url in content.urls:
        try:
            url_analyses.append(analyze_url(url))
        except ValueError:
            continue  # malformed link: ignored, never fetched
    full_text = f"{content.subject}\n{content.body}"
    signals = (
        _content_signals(full_text)
        + _link_signal(url_analyses)
        + _link_mismatch_signals(content.html_links)
        + _attachment_signals(content.attachment_names)
        + _sender_signals(content.sender, content.reply_to)
    )
    return EmailAnalysis(content=content, signals=signals, url_analyses=url_analyses)
