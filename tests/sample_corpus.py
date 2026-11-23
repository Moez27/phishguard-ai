"""Build a tiny synthetic corpus with the same on-disk layout as the real datasets.

Used ONLY by the test suite to exercise parsing, preparation and training code.
It is not training data and its metrics mean nothing.
"""

from __future__ import annotations

import itertools
from pathlib import Path

HAM_TOPICS = [
    "budget review",
    "team lunch",
    "release notes",
    "code review",
    "hiking trip",
    "conference agenda",
    "server upgrade",
    "book club",
]
HAM_PEOPLE = ["alice", "bob", "carol", "dave", "erin", "frank"]
PHISH_BRANDS = ["paypal", "your bank", "apple id", "amazon", "netflix", "microsoft"]
PHISH_HOOKS = [
    "account suspended",
    "unusual sign in",
    "password expires",
    "payment failed",
    "verify identity",
    "billing problem",
    "locked account",
    "security alert",
]


def ham_messages(n: int) -> list[str]:
    combos = itertools.islice(itertools.product(HAM_TOPICS, HAM_PEOPLE), n)
    return [
        f"From: {person}@example.org\nTo: team@example.org\nSubject: Re: {topic}\n\n"
        f"Hi all, here are my thoughts on the {topic}. {person} will share the slides "
        f"tomorrow at the weekly meeting. Thanks, {person}\n"
        for topic, person in combos
    ]


def phishing_messages(n: int) -> list[str]:
    combos = itertools.islice(itertools.product(PHISH_HOOKS, PHISH_BRANDS), n)
    return [
        f"From: security@{brand.replace(' ', '')}-alerts.example\nSubject: Urgent: {hook}\n"
        "Content-Type: text/html\n\n"
        f"<html><body><p>Dear customer, your {brand} {hook}. Verify your password "
        f'immediately <a href="http://192.0.2.1/{brand.replace(" ", "")}/login">here</a> '
        "or your account will be closed within 24 hours.</p></body></html>\n"
        for hook, brand in combos
    ]


def write_sample_corpus(raw_dir: Path, n_ham: int = 40, n_phish: int = 40) -> None:
    """Create data/raw-like folders under ``raw_dir``."""
    easy = raw_dir / "spamassassin" / "easy_ham"
    easy.mkdir(parents=True)
    for i, msg in enumerate(ham_messages(n_ham)):
        (easy / f"{i:05d}.msg").write_text(msg, encoding="utf-8")
    (easy / "cmds").write_text("mv 00001 ...", encoding="utf-8")  # must be ignored

    spam = raw_dir / "spamassassin" / "spam"  # must be ignored (not phishing)
    spam.mkdir(parents=True)
    (spam / "00001.spam").write_text("Subject: cheap pills\n\nbuy now", encoding="utf-8")

    nazario = raw_dir / "nazario"
    nazario.mkdir(parents=True)
    mbox = "".join(
        f"From MAILER-DAEMON Mon Jan  1 00:00:00 2024\n{msg}\n"
        for msg in phishing_messages(n_phish)
    )
    (nazario / "phishing-sample.mbox").write_text(mbox, encoding="utf-8")
