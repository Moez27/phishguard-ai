"""Load the raw corpora into a single, deduplicated, labelled table.

Labels
------
* ``0`` = legitimate: SpamAssassin ``easy_ham*`` and ``hard_ham*`` folders
* ``1`` = phishing:   every message of the Nazario Phishing Corpus (mbox files)

SpamAssassin ``spam*`` folders are deliberately ignored: generic spam is not
phishing, and mixing it in would teach the model "spam vs ham" instead.
"""

from __future__ import annotations

import hashlib
import logging
import mailbox
import re
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

import pandas as pd

from ml.preprocess import build_model_text, normalize_text, parse_email

logger = logging.getLogger(__name__)

SPAMASSASSIN_DIRNAME = "spamassassin"
NAZARIO_DIRNAME = "nazario"
HAM_FOLDER_PREFIXES = ("easy_ham", "hard_ham")
IGNORED_FILENAMES = {"cmds", ".gitkeep", "readme", "readme.txt", "readme.md"}

LABEL_LEGITIMATE = 0
LABEL_PHISHING = 1
LABEL_NAMES = {LABEL_LEGITIMATE: "legitimate", LABEL_PHISHING: "phishing"}

COLUMNS = ["id", "source", "subject", "body", "label"]

# Raw files larger than this are skipped (corrupt or abusive input).
MAX_RAW_MESSAGE_BYTES = 2 * 1024 * 1024


class DatasetError(RuntimeError):
    """Raised when the raw or processed dataset is missing or invalid."""


@dataclass
class DatasetStats:
    """Counts reported by :func:`build_dataset` (saved next to the CSV)."""

    raw_by_source: dict[str, int] = field(default_factory=dict)
    skipped_unreadable: int = 0
    skipped_empty: int = 0
    duplicates_removed: int = 0
    final_by_label: dict[str, int] = field(default_factory=dict)
    final_total: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class RawMessage:
    source: str
    label: int
    raw: bytes


# --- Readers -----------------------------------------------------------------


def iter_spamassassin(root: Path) -> Iterator[RawMessage]:
    """Yield legitimate messages from SpamAssassin ham folders under ``root``."""
    if not root.is_dir():
        return
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        name = folder.name.lower()
        if not name.startswith(HAM_FOLDER_PREFIXES):
            logger.info("Ignoring SpamAssassin folder %s (not ham)", folder.name)
            continue
        source = f"spamassassin_{name}"
        for path in sorted(folder.rglob("*")):
            if not path.is_file() or path.name.lower() in IGNORED_FILENAMES:
                continue
            if path.stat().st_size > MAX_RAW_MESSAGE_BYTES:
                continue
            yield RawMessage(source, LABEL_LEGITIMATE, path.read_bytes())


def iter_nazario(root: Path) -> Iterator[RawMessage]:
    """Yield phishing messages from every mbox file under ``root``."""
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name.lower() in IGNORED_FILENAMES:
            continue
        box = mailbox.mbox(str(path), create=False)
        try:
            for key in box.iterkeys():
                try:
                    raw = box.get_bytes(key)
                except Exception as exc:  # one corrupt entry must not stop the load
                    logger.warning("Skipping unreadable entry %s in %s: %s", key, path.name, exc)
                    continue
                if len(raw) <= MAX_RAW_MESSAGE_BYTES:
                    yield RawMessage(NAZARIO_DIRNAME, LABEL_PHISHING, raw)
        finally:
            box.close()


# --- Builder -----------------------------------------------------------------


# --- Corpus-artifact scrubbing ----------------------------------------------
# These patterns identify *how the corpora were collected*, not phishing itself.
# Leaving them in lets the model recognise the source corpus instead of the
# content (data leakage). They are removed from BOTH classes, identically.

# Nazario corpus: the collector's own mailbox/domain/name, often inserted by
# phishing kits ("Dear jose@monkey.org", "monkey.org Webmail").
_COLLECTOR_RE = re.compile(r"(?i)\b(?:jose|nazario|monkey)\b(?:\.org)?")
# SpamAssassin ham: Mailman list footers ("____\nXyz mailing list\n...listinfo...")
_LIST_FOOTER_RE = re.compile(
    r"(?ms)^_{10,}[ \t]*\n(?=.{0,400}?(?:mailing list|listinfo|unsubscribe)).*\Z"
)
# SpamAssassin ham: SourceForge sponsor footers
_SPONSOR_FOOTER_RE = re.compile(
    r"(?ims)^-{10,}[ \t]*\n(?:this sf\.net email is sponsored|this email is sponsored)"
    r".*?(?=^_{10,}|\Z)"
)
# SpamAssassin ham: RSS-to-email gateway lines ("URL: http://..." / "Date: ...")
_FEED_LINE_RE = re.compile(r"(?im)^(?:url|date):[ \t].*$")


def scrub_corpus_artifacts(text: str) -> str:
    """Remove corpus-collection artifacts (see comments above). Training data only."""
    if not text:
        return ""
    text = _SPONSOR_FOOTER_RE.sub("", text)
    text = _LIST_FOOTER_RE.sub("", text)
    text = _FEED_LINE_RE.sub("", text)
    return _COLLECTOR_RE.sub(" ", text)


def text_fingerprint(subject: str, body: str) -> str:
    """Stable hash of the normalised text, used to detect duplicates."""
    normalized = normalize_text(build_model_text(subject, body))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def build_dataset(raw_dir: Path) -> tuple[pd.DataFrame, DatasetStats]:
    """Parse both corpora, drop empty messages and duplicates.

    Deduplication happens here, *before* any train/test split, so the same
    message can never end up in both sets.
    """
    spam_root = raw_dir / SPAMASSASSIN_DIRNAME
    nazario_root = raw_dir / NAZARIO_DIRNAME
    missing = [str(p) for p in (spam_root, nazario_root) if not p.is_dir()]
    if missing:
        raise DatasetError(
            "Missing dataset folder(s): " + ", ".join(missing) + ". See data/README.md."
        )

    stats = DatasetStats()
    rows: list[dict] = []
    seen: dict[str, int] = {}  # fingerprint -> label

    def _messages() -> Iterator[RawMessage]:
        yield from iter_spamassassin(spam_root)
        yield from iter_nazario(nazario_root)

    for msg in _messages():
        stats.raw_by_source[msg.source] = stats.raw_by_source.get(msg.source, 0) + 1
        try:
            parsed = parse_email(msg.raw)
        except Exception:  # noqa: BLE001 - malformed messages are counted and skipped
            stats.skipped_unreadable += 1
            continue
        subject = scrub_corpus_artifacts(parsed.subject).strip()
        body = scrub_corpus_artifacts(parsed.body).strip()
        if not normalize_text(build_model_text(subject, body)):
            stats.skipped_empty += 1
            continue
        fingerprint = text_fingerprint(subject, body)
        if fingerprint in seen:
            stats.duplicates_removed += 1
            continue
        seen[fingerprint] = msg.label
        rows.append(
            {
                "id": fingerprint,
                "source": msg.source,
                "subject": subject,
                "body": body,
                "label": msg.label,
            }
        )

    df = pd.DataFrame(rows, columns=COLUMNS)
    stats.final_total = len(df)
    stats.final_by_label = {
        LABEL_NAMES[label]: int((df["label"] == label).sum()) for label in LABEL_NAMES
    }
    return df, stats


# --- Processed CSV -----------------------------------------------------------


def load_processed(csv_path: Path, min_per_class: int = 10) -> pd.DataFrame:
    """Load and validate ``emails.csv`` produced by ``scripts/prepare_data.py``."""
    if not csv_path.is_file():
        raise DatasetError(
            f"Processed dataset not found: {csv_path}. Run: python -m scripts.prepare_data"
        )
    df = pd.read_csv(csv_path, dtype={"id": str, "source": str, "subject": str, "body": str})
    missing_cols = set(COLUMNS) - set(df.columns)
    if missing_cols:
        raise DatasetError(f"Processed dataset is missing columns: {sorted(missing_cols)}")
    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")
    if not set(df["label"].unique()) <= set(LABEL_NAMES):
        raise DatasetError("Labels must be 0 (legitimate) or 1 (phishing).")
    if df["id"].duplicated().any():
        raise DatasetError("Processed dataset contains duplicate ids (deduplication failed).")
    counts = df["label"].value_counts()
    for label, name in LABEL_NAMES.items():
        if counts.get(label, 0) < min_per_class:
            raise DatasetError(
                f"Not enough '{name}' samples: {counts.get(label, 0)} (minimum {min_per_class})."
            )
    return df
