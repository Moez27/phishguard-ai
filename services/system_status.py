"""Inspect the local environment: datasets, trained model and database.

The home page uses these checks to show the real state of the platform
instead of hardcoded "ready" indicators.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from config.settings import Settings

SPAMASSASSIN_DIRNAME = "spamassassin"
NAZARIO_DIRNAME = "nazario"


@dataclass(frozen=True)
class ComponentStatus:
    """Availability of one platform component."""

    name: str
    available: bool
    detail: str
    next_step: str | None = None


def _count_files(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    return sum(1 for p in directory.rglob("*") if p.is_file() and p.name != ".gitkeep")


def dataset_status(settings: Settings) -> ComponentStatus:
    """Report whether both raw corpora are present in ``data/raw``."""
    spam_files = _count_files(settings.raw_data_dir / SPAMASSASSIN_DIRNAME)
    nazario_files = _count_files(settings.raw_data_dir / NAZARIO_DIRNAME)
    available = spam_files > 0 and nazario_files > 0
    detail = f"SpamAssassin: {spam_files} files · Nazario: {nazario_files} files"
    next_step = None if available else "Download the corpora as described in data/README.md."
    return ComponentStatus("Datasets", available, detail, next_step)


def model_status(settings: Settings) -> ComponentStatus:
    """Report whether a trained model and its metadata exist."""
    has_model = settings.model_path.is_file()
    has_metadata = settings.model_metadata_path.is_file()
    available = has_model and has_metadata
    if available:
        detail = f"Model file: {settings.model_path.name}"
    elif has_model:
        detail = "Model file found but metadata is missing."
    else:
        detail = "No trained model found."
    next_step = (
        None if available else "Run: python -m scripts.prepare_data, then python -m ml.train"
    )
    return ComponentStatus("ML model", available, detail, next_step)


def database_status(settings: Settings) -> ComponentStatus:
    """Report whether the SQLite history database exists."""
    available = settings.db_path.is_file()
    detail = (
        f"History database: {settings.db_path.name}"
        if available
        else "History database not created yet."
    )
    next_step = None if available else "Created automatically on the first saved analysis."
    return ComponentStatus("Analysis history", available, detail, next_step)


def read_model_metadata(settings: Settings) -> dict | None:
    """Metadata written by ml/train.py (real evaluation results), or None."""
    path = settings.model_metadata_path
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def collect_status(settings: Settings) -> list[ComponentStatus]:
    """Return the status of every platform component."""
    return [dataset_status(settings), model_status(settings), database_status(settings)]
