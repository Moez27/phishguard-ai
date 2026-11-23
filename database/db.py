"""SQLite connection and schema for the analysis history.

Privacy by design: the table stores the verdict, scores and minimal metadata.
The analysed email text is stored ONLY if ``PHISHGUARD_STORE_EMAIL_BODY=true``
(``content`` column, NULL otherwise).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id       TEXT    NOT NULL UNIQUE,
    created_at      TEXT    NOT NULL,              -- ISO 8601, UTC
    analysis_type   TEXT    NOT NULL CHECK (analysis_type IN ('email', 'url')),
    verdict         TEXT    NOT NULL CHECK (verdict IN ('legitimate', 'suspect', 'phishing')),
    risk_score      REAL    NOT NULL CHECK (risk_score BETWEEN 0 AND 1),
    rule_score      REAL    NOT NULL CHECK (rule_score BETWEEN 0 AND 1),
    ml_probability  REAL
        CHECK (ml_probability IS NULL OR ml_probability BETWEEN 0 AND 1),
    model_version   TEXT,
    target          TEXT    NOT NULL DEFAULT '',   -- URL host or email sender domain
    signal_codes    TEXT    NOT NULL DEFAULT '',   -- comma-separated indicator codes
    num_signals     INTEGER NOT NULL DEFAULT 0,
    metadata_json   TEXT    NOT NULL DEFAULT '{}',
    duration_ms     REAL    NOT NULL DEFAULT 0,
    content         TEXT                           -- NULL unless STORE_EMAIL_BODY=true
);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses (created_at);
CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses (verdict);
"""


@contextmanager
def connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Open a connection, commit on success, roll back on error, always close."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path) -> None:
    """Create the schema if needed (idempotent)."""
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
