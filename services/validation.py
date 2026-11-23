"""Input validation for everything a user can submit.

Every function returns a cleaned value or raises :class:`ValidationError`
whose message is safe and understandable to show in the interface.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePath
from urllib.parse import urlsplit

from config.settings import Settings

ALLOWED_URL_SCHEMES = ("http", "https")
# "javascript:", "data:", "file:" ... but not "example.com:8080" (dot) nor "host:8080" (port)
_EXPLICIT_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+-]*):(?!\d+(?:[/?#]|$))")
# Share of control characters above which a text is considered binary
_MAX_CONTROL_CHAR_RATIO = 0.05


class ValidationError(ValueError):
    """Invalid user input. The message is intended for the end user."""


def _looks_binary(text: str) -> bool:
    if "\x00" in text:
        return True
    sample = text[:5000]
    controls = sum(1 for c in sample if ord(c) < 32 and c not in "\r\n\t\f")
    return bool(sample) and controls / len(sample) > _MAX_CONTROL_CHAR_RATIO


def validate_email_text(text: str | None, settings: Settings) -> str:
    """Validate pasted email content."""
    if text is None or not text.strip():
        raise ValidationError("Please paste the content of an email to analyse.")
    if len(text) > settings.max_email_chars:
        raise ValidationError(
            f"The email is too long ({len(text):,} characters). "
            f"The maximum is {settings.max_email_chars:,} characters."
        )
    if _looks_binary(text):
        raise ValidationError(
            "The content looks like binary data, not an email. Only plain text is accepted."
        )
    return text.strip()


def validate_upload(filename: str | None, data: bytes | None, settings: Settings) -> str:
    """Validate an uploaded file and return its text content.

    Only plain-text files are accepted. The file is decoded as text, never executed.
    """
    if not filename or data is None:
        raise ValidationError("No file was received.")
    extension = PurePath(filename).suffix.lower()
    if extension not in settings.allowed_upload_extensions:
        allowed = ", ".join(settings.allowed_upload_extensions)
        raise ValidationError(
            f"Unsupported file type '{extension or 'none'}'. Accepted format: {allowed}."
        )
    if not data:
        raise ValidationError("The uploaded file is empty.")
    if len(data) > settings.max_upload_bytes:
        raise ValidationError(
            f"The file is too large ({len(data) / 1024:.0f} KB). "
            f"The maximum is {settings.max_upload_bytes / 1024:.0f} KB."
        )
    if b"\x00" in data:
        raise ValidationError("The file contains binary data. Only plain-text files are accepted.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("cp1252", errors="replace")
    return validate_email_text(text, settings)


def validate_url(url: str | None, settings: Settings) -> str:
    """Validate a URL typed by the user and return it in a normalised form.

    A missing scheme is accepted (``example.com/login`` -> ``http://example.com/login``)
    because phishing links are often shared that way. The URL is never opened.
    """
    if url is None or not url.strip():
        raise ValidationError("Please enter a URL to analyse.")
    url = url.strip()
    if len(url) > settings.max_url_length:
        raise ValidationError(
            f"The URL is too long ({len(url):,} characters). "
            f"The maximum is {settings.max_url_length:,} characters."
        )
    if any(c.isspace() for c in url) or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValidationError("The URL must not contain spaces or control characters.")

    scheme_match = _EXPLICIT_SCHEME.match(url)
    if scheme_match and scheme_match.group(1).lower() not in ALLOWED_URL_SCHEMES:
        raise ValidationError(
            f"Unsupported URL scheme '{scheme_match.group(1).lower()}:'. "
            "Only http and https links can be analysed."
        )
    candidate = url if "://" in url else f"http://{url}"
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        _ = parts.port  # raises ValueError on an invalid port
    except ValueError as exc:
        raise ValidationError(f"This URL is not valid: {_safe_echo(str(exc))}.") from None

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise ValidationError(
            f"Unsupported URL scheme '{_safe_echo(scheme)}:'. "
            "Only http and https links can be analysed."
        )
    if not hostname:
        raise ValidationError("The URL has no domain name or IP address.")
    if not _is_ip(hostname) and "." not in hostname:
        raise ValidationError(
            f"'{_safe_echo(hostname)}' is not a complete domain name (expected e.g. example.com)."
        )
    return candidate


_UNSAFE_ECHO = re.compile(r"[^A-Za-z0-9 .,:'\-]")


def _safe_echo(text: str, limit: int = 80) -> str:
    """Make user-controlled text safe to show in a (Markdown-rendered) message."""
    return _UNSAFE_ECHO.sub("?", text)[:limit]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
