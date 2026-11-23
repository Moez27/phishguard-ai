"""Email parsing and text normalisation shared by training AND inference.

Using the exact same functions in both places guarantees the model sees text
prepared the same way at prediction time as during training.

Security notes
--------------
* Attachments are never decoded to disk nor executed: non-text parts are skipped.
* HTML is converted to plain text with BeautifulSoup's pure-Python parser;
  no script is run and no remote resource (image, link) is fetched.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass
from email.header import decode_header, make_header
from email.message import Message

from bs4 import BeautifulSoup

# --- Regular expressions -----------------------------------------------------

# URLs with an explicit scheme or starting with "www."
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"')\]]+")
# Lengths are bounded like RFC 5321 (local part <= 64, domain <= 253, label <= 63).
# Unbounded "+" here caused catastrophic backtracking: "a.a.a.a..." (50k chars)
# took ~14 s, a denial-of-service vector. Bounded, matching is linear.
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}\b")
NUMBER_RE = re.compile(r"\b\d+(?:[.,]\d+)*\b")
WHITESPACE_RE = re.compile(r"\s+")

# Placeholder tokens: the model learns "there is a URL" without memorising
# specific domains or addresses (which would leak the corpus origin).
URL_PLACEHOLDER = " urltoken "
EMAIL_PLACEHOLDER = " emailtoken "
NUMBER_PLACEHOLDER = " numtoken "

# Upper bounds per message (protect memory/CPU).
MAX_TEXT_CHARS = 50_000
MAX_LINKS = 100


@dataclass(frozen=True)
class ParsedEmail:
    """Content extracted from a raw email."""

    subject: str
    body: str
    has_html: bool
    attachment_count: int
    # Fields below are used by the analysers only (never by the ML model).
    sender: str = ""
    reply_to: str = ""
    attachment_names: tuple[str, ...] = ()
    html_links: tuple[tuple[str, str], ...] = ()  # (visible text, href)
    has_headers: bool = False


# --- HTML -----------------------------------------------------------------------


def html_to_text(html: str) -> str:
    """Convert HTML to visible plain text, keeping link targets as text.

    ``<a href="X">label</a>`` becomes ``label X`` so the URL remains available
    to the analysers (it is never visited).
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "head", "title", "meta", "noscript"]):
        tag.decompose()
    for link in soup.find_all("a", href=True):
        href = str(link.get("href", "")).strip()
        if href and not href.lower().startswith(("mailto:", "#", "javascript:")):
            link.append(f" {href} ")
    return soup.get_text(" ")


def extract_html_links(html: str) -> list[tuple[str, str]]:
    """Return ``(visible text, href)`` pairs of the HTML links (never visited)."""
    soup = BeautifulSoup(html, "html.parser")
    links: list[tuple[str, str]] = []
    for link in soup.find_all("a", href=True):
        href = str(link.get("href", "")).strip()
        if href and not href.lower().startswith(("mailto:", "#")):
            text = " ".join(link.get_text(" ").split())[:300]
            links.append((text, href[:2048]))
        if len(links) >= MAX_LINKS:
            break
    return links


# --- Raw email parsing -------------------------------------------------------


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:  # unknown charset name
        return payload.decode("latin-1", errors="replace")


def _decode_text(raw: str) -> str:
    """Decode RFC 2047 encoded-words; keep the raw text if malformed."""
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(str(raw)))).strip()
    except Exception:  # noqa: BLE001 - malformed/unknown charset: keep the raw text
        return str(raw).strip()


def _decoded_header(msg: Message, name: str) -> str:
    return _decode_text(str(msg.get(name, "") or ""))[:500]


def _safe_subject(msg: Message) -> str:
    """Return the decoded subject, or "" if absent."""
    return _decoded_header(msg, "Subject")


def parse_email(raw: bytes | str) -> ParsedEmail:
    """Parse a raw RFC 822 email into subject and plain-text body.

    Headers other than the subject are intentionally discarded (see
    ``data/README.md``: headers leak the corpus origin).
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments = 0
    attachment_names: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        content_type = part.get_content_type()
        if "attachment" in disposition or part.get_filename():
            attachments += 1
            # Only the declared file NAME is read; the content is never decoded or executed.
            name = _decode_text(part.get_filename() or "")
            if name:
                attachment_names.append(name[:255])
            continue
        if content_type == "text/plain":
            plain_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))

    if plain_parts:
        body = "\n".join(plain_parts)
    elif html_parts:
        body = "\n".join(html_to_text(h) for h in html_parts)
    else:
        body = ""

    links: list[tuple[str, str]] = []
    for html in html_parts:
        links.extend(extract_html_links(html))

    return ParsedEmail(
        subject=_safe_subject(msg)[:1000],
        body=body[:MAX_TEXT_CHARS],
        has_html=bool(html_parts),
        attachment_count=attachments,
        sender=_decoded_header(msg, "From"),
        reply_to=_decoded_header(msg, "Reply-To"),
        attachment_names=tuple(attachment_names),
        html_links=tuple(links[:MAX_LINKS]),
        has_headers=bool(msg.keys()),
    )


# --- Normalisation ---------------------------------------------------------


def extract_urls(text: str) -> list[str]:
    """Return URLs found in ``text`` (order preserved, duplicates removed)."""
    seen: dict[str, None] = {}
    for match in URL_RE.findall(text or ""):
        seen.setdefault(match.rstrip(".,;:!?"), None)
    return list(seen)


def normalize_text(text: str) -> str:
    """Normalise text for the TF-IDF model.

    Lower-cases, replaces URLs, email addresses and numbers by placeholder
    tokens, and collapses whitespace. Must stay a module-level function: it is
    referenced by the saved scikit-learn pipeline.
    """
    if not text:
        return ""
    text = text[:MAX_TEXT_CHARS].lower()
    text = URL_RE.sub(URL_PLACEHOLDER, text)
    text = EMAIL_RE.sub(EMAIL_PLACEHOLDER, text)
    text = NUMBER_RE.sub(NUMBER_PLACEHOLDER, text)
    return WHITESPACE_RE.sub(" ", text).strip()


def build_model_text(subject: str, body: str) -> str:
    """Combine subject and body into the single text given to the model."""
    return f"{subject or ''}\n{body or ''}".strip()
