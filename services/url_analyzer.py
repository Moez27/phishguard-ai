"""Offline lexical and structural analysis of a URL.

SECURITY: the URL is only parsed as a string. It is never opened, resolved
(no DNS), fetched or previewed. No external reputation service is queried,
and results must not claim otherwise.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

import tldextract

from services import indicators as ind
from services.signals import Category, Signal, combine_weights

OFFICIAL_DOMAINS = frozenset(d for domains in ind.BRANDS.values() for d in domains)


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # Empty suffix_list_urls + no cache dir = bundled Public Suffix List snapshot,
    # strictly no network access and no disk writes.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass(frozen=True)
class UrlFeatures:
    """Lexical/structural features of a URL (all computed offline)."""

    url: str
    scheme: str
    host: str
    registered_domain: str
    subdomain: str
    tld: str
    port: int | None
    path: str
    length: int
    host_length: int
    num_dots: int
    num_hyphens_host: int
    num_digits_host: int
    num_subdomains: int
    num_query_params: int
    uses_https: bool
    has_ip_host: bool
    has_at_symbol: bool
    has_punycode: bool
    has_non_ascii: bool
    has_embedded_redirect: bool
    is_shortener: bool
    suspicious_tld: bool
    keywords: tuple[str, ...]
    impersonated_brands: tuple[str, ...]
    executable_extension: str | None


@dataclass(frozen=True)
class UrlAnalysis:
    features: UrlFeatures
    signals: list[Signal] = field(default_factory=list)

    @property
    def rule_score(self) -> float:
        return combine_weights(s.weight for s in self.signals)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        # Also catch decimal/hex obfuscated IPv4 such as http://3232235777/
        return host.isdigit() or (host.startswith("0x") and len(host) > 2)
    return True


def _brand_mismatches(host: str, registered: str, path: str) -> tuple[str, ...]:
    """Brands named in the subdomain/domain/path while the registered domain is not theirs."""
    haystack = f"{host} {path}".lower()
    found = []
    for brand, official in ind.BRANDS.items():
        if brand in haystack and registered.lower() not in official:
            found.append(brand)
    return tuple(found)


def extract_features(url: str) -> UrlFeatures:
    """Compute features for an already-validated URL (see services.validation)."""
    candidate = url if "://" in url else f"http://{url}"
    parts = urlsplit(candidate)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    ext = _extractor()(host)
    is_ip = _is_ip(host)
    if is_ip:
        registered, subdomain, tld = "", "", ""
    elif ext.suffix:
        registered, subdomain, tld = f"{ext.domain}.{ext.suffix}", ext.subdomain, ext.suffix
    else:
        # TLD unknown to the Public Suffix List (e.g. reserved ".example", new or fake
        # TLDs): fall back to the last two labels instead of a bare label.
        labels = host.split(".")
        registered = ".".join(labels[-2:])
        subdomain = ".".join(labels[:-2])
        tld = labels[-1] if len(labels) > 1 else ""
    path = unquote(parts.path or "")
    lowered = candidate.lower()

    suffix = PurePosixPath(path.lower()).suffix
    executable = suffix if suffix in ind.URL_DOWNLOAD_EXTENSIONS else None
    # "login"/"account" on a brand's own official domain is normal, not suspicious.
    keywords = (
        () if registered in OFFICIAL_DOMAINS else tuple(k for k in ind.URL_KEYWORDS if k in lowered)
    )

    return UrlFeatures(
        url=candidate,
        scheme=parts.scheme.lower(),
        host=host,
        registered_domain=registered,
        subdomain=subdomain,
        tld=tld,
        port=port,
        path=path,
        length=len(candidate),
        host_length=len(host),
        num_dots=host.count("."),
        num_hyphens_host=host.replace("xn--", "").count("-"),
        num_digits_host=sum(c.isdigit() for c in host),
        num_subdomains=len([p for p in subdomain.split(".") if p]) if subdomain else 0,
        num_query_params=len([q for q in parts.query.split("&") if q]),
        uses_https=parts.scheme.lower() == "https",
        has_ip_host=is_ip,
        has_at_symbol="@" in parts.netloc,
        has_punycode="xn--" in host,
        has_non_ascii=any(ord(c) > 127 for c in host),
        has_embedded_redirect="//" in path or "http" in parts.query.lower(),
        is_shortener=registered in ind.URL_SHORTENERS or host in ind.URL_SHORTENERS,
        suspicious_tld=(tld.split(".")[-1] if tld else "") in ind.SUSPICIOUS_TLDS,
        keywords=keywords,
        impersonated_brands=() if is_ip else _brand_mismatches(host, registered, path),
        executable_extension=executable,
    )


def _signals(f: UrlFeatures) -> list[Signal]:
    s: list[Signal] = []

    def add(code: str, title: str, detail: str, weight: float) -> None:
        s.append(Signal(code, Category.URL, title, detail, weight))

    if f.has_ip_host:
        add("url_ip_host", "IP address instead of a domain name",
            f"The link points to the raw address {f.host}. Legitimate services almost "
            "always use a domain name.", ind.W_IP_HOST)  # fmt: skip
    if f.has_at_symbol:
        add("url_at_symbol", "'@' symbol in the address",
            "Everything before '@' is ignored by the browser; this trick hides the real "
            "destination.", ind.W_AT_SYMBOL)  # fmt: skip
    if f.has_punycode or f.has_non_ascii:
        add("url_punycode", "Internationalised (look-alike) domain",
            f"The domain '{f.host}' uses encoded or non-Latin characters, which can imitate "
            "a well-known name.", ind.W_PUNYCODE)  # fmt: skip
    if f.impersonated_brands:
        brands = ", ".join(f.impersonated_brands)
        add("url_brand_mismatch", "Brand name used on an unrelated domain",
            f"The address mentions {brands} but the actual domain is "
            f"'{f.registered_domain}'.", ind.W_BRAND_MISMATCH)  # fmt: skip
    if f.is_shortener:
        add("url_shortener", "URL shortener",
            f"'{f.registered_domain or f.host}' hides the final destination.",
            ind.W_SHORTENER)  # fmt: skip
    if f.keywords:
        weight = ind.W_KEYWORD_MANY if len(f.keywords) >= 2 else ind.W_KEYWORD_ONE
        add("url_keywords", "Sensitive keywords in the address",
            f"Found: {', '.join(f.keywords)}.", weight)  # fmt: skip
    if f.suspicious_tld:
        add("url_suspicious_tld", "Top-level domain often abused",
            f"'.{f.tld}' domains are over-represented in abuse reports (weak signal).",
            ind.W_SUSPICIOUS_TLD)  # fmt: skip
    if not f.uses_https:
        add("url_no_https", "No HTTPS",
            "The link is not encrypted. Note: HTTPS alone does not prove a site is safe.",
            ind.W_NO_HTTPS)  # fmt: skip
    if f.length > ind.VERY_LONG_URL:
        add("url_very_long", "Very long address",
            f"{f.length} characters; long URLs can hide the real domain.",
            ind.W_VERY_LONG_URL)  # fmt: skip
    elif f.length > ind.LONG_URL:
        add("url_long", "Long address", f"{f.length} characters.", ind.W_LONG_URL)
    if f.num_subdomains >= 3:
        add("url_many_subdomains", "Many subdomains",
            f"{f.num_subdomains} levels before '{f.registered_domain}' "
            f"('{f.subdomain}').", ind.W_MANY_SUBDOMAINS)  # fmt: skip
    if f.num_hyphens_host >= 3:
        add("url_many_hyphens", "Many hyphens in the domain",
            f"{f.num_hyphens_host} hyphens in '{f.host}'.", ind.W_MANY_HYPHENS)  # fmt: skip
    if f.port is not None and f.port not in (80, 443):
        add("url_port", "Non-standard port", f"Port {f.port} is specified explicitly.",
            ind.W_NON_STANDARD_PORT)  # fmt: skip
    if f.has_embedded_redirect:
        add("url_redirect", "Embedded redirection",
            "The path or parameters contain another address, typical of redirect chains.",
            ind.W_EMBEDDED_REDIRECT)  # fmt: skip
    if f.executable_extension:
        add("url_executable", "Link to a potentially dangerous file",
            f"The link ends with '{f.executable_extension}'. Do not download or open it.",
            ind.W_EXECUTABLE_LINK)  # fmt: skip
    if not f.has_ip_host and f.num_digits_host >= 5:
        add("url_digits", "Many digits in the domain", f"'{f.host}'.", ind.W_DIGIT_HEAVY_HOST)
    return s


def analyze_url(url: str) -> UrlAnalysis:
    """Analyse a validated URL. Never contacts the network."""
    features = extract_features(url)
    return UrlAnalysis(features=features, signals=_signals(features))
