"""Read/write access to the analysis history. All SQL is parameterised."""

from __future__ import annotations

import json
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pandas as pd

from database.db import connect, init_db

VERDICTS = ("legitimate", "suspect", "phishing")
TYPES = ("email", "url")


@dataclass(frozen=True)
class AnalysisRecord:
    public_id: str
    created_at: datetime
    analysis_type: str
    verdict: str
    risk_score: float
    rule_score: float
    ml_probability: float | None
    model_version: str | None
    target: str
    signal_codes: tuple[str, ...]
    metadata: dict


@dataclass(frozen=True)
class HistoryStats:
    total: int
    by_verdict: dict[str, int]
    by_type: dict[str, int]
    average_risk: float | None
    last_analysis_at: datetime | None


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _row_to_record(row) -> AnalysisRecord:
    return AnalysisRecord(
        public_id=row["public_id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        analysis_type=row["analysis_type"],
        verdict=row["verdict"],
        risk_score=row["risk_score"],
        rule_score=row["rule_score"],
        ml_probability=row["ml_probability"],
        model_version=row["model_version"],
        target=row["target"],
        signal_codes=tuple(c for c in row["signal_codes"].split(",") if c),
        metadata=json.loads(row["metadata_json"] or "{}"),
    )


# --- Write -------------------------------------------------------------------


def insert_analysis(
    db_path: Path,
    *,
    analysis_type: str,
    verdict: str,
    risk_score: float,
    rule_score: float,
    ml_probability: float | None,
    model_version: str | None,
    target: str,
    signal_codes: list[str],
    metadata: dict,
    duration_ms: float,
    content: str | None = None,
    created_at: datetime | None = None,
) -> str:
    """Insert one analysis and return its public identifier."""
    if analysis_type not in TYPES:
        raise ValueError(f"Unknown analysis type: {analysis_type}")
    if verdict not in VERDICTS:
        raise ValueError(f"Unknown verdict: {verdict}")
    init_db(db_path)
    public_id = uuid.uuid4().hex[:12]
    created = (created_at or _now()).astimezone(UTC).isoformat()
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO analyses (public_id, created_at, analysis_type, verdict, risk_score,
                rule_score, ml_probability, model_version, target, signal_codes, num_signals,
                metadata_json, duration_ms, content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                public_id,
                created,
                analysis_type,
                verdict,
                round(float(risk_score), 6),
                round(float(rule_score), 6),
                None if ml_probability is None else round(float(ml_probability), 6),
                model_version,
                target[:255],
                ",".join(signal_codes),
                len(signal_codes),
                json.dumps(metadata, default=str),
                float(duration_ms),
                content,
            ),
        )
    return public_id


# --- Read --------------------------------------------------------------------


def get_stats(db_path: Path) -> HistoryStats:
    if not db_path.is_file():
        return HistoryStats(0, dict.fromkeys(VERDICTS, 0), dict.fromkeys(TYPES, 0), None, None)
    init_db(db_path)
    with connect(db_path) as conn:
        total, avg, last = conn.execute(
            "SELECT COUNT(*), AVG(risk_score), MAX(created_at) FROM analyses"
        ).fetchone()
        by_verdict = dict.fromkeys(VERDICTS, 0)
        for row in conn.execute("SELECT verdict, COUNT(*) FROM analyses GROUP BY verdict"):
            by_verdict[row[0]] = row[1]
        by_type = dict.fromkeys(TYPES, 0)
        for row in conn.execute("SELECT analysis_type, COUNT(*) FROM analyses GROUP BY 1"):
            by_type[row[0]] = row[1]
    return HistoryStats(
        total=total,
        by_verdict=by_verdict,
        by_type=by_type,
        average_risk=avg,
        last_analysis_at=datetime.fromisoformat(last) if last else None,
    )


def recent_analyses(db_path: Path, limit: int = 10) -> list[AnalysisRecord]:
    if not db_path.is_file():
        return []
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY created_at DESC, id DESC LIMIT ?", (int(limit),)
        ).fetchall()
    return [_row_to_record(r) for r in rows]


def daily_activity(db_path: Path, days: int = 30, today: date | None = None) -> pd.DataFrame:
    """Analyses per UTC day and verdict for the last ``days`` days (zeros included)."""
    today = today or _now().date()
    start = today - timedelta(days=days - 1)
    index = pd.MultiIndex.from_product(
        [pd.date_range(start, today, freq="D").date, VERDICTS], names=["day", "verdict"]
    )
    counts = pd.Series(0, index=index, name="count")
    if db_path.is_file():
        init_db(db_path)
        with connect(db_path) as conn:
            rows = conn.execute(
                """
                SELECT substr(created_at, 1, 10) AS day, verdict, COUNT(*) AS n
                FROM analyses WHERE substr(created_at, 1, 10) >= ? GROUP BY 1, 2
                """,
                (start.isoformat(),),
            ).fetchall()
        for row in rows:
            key = (date.fromisoformat(row["day"]), row["verdict"])
            if key in counts.index:
                counts[key] = row["n"]
    return counts.reset_index()


def risk_scores(db_path: Path) -> list[tuple[str, float]]:
    """(verdict, risk_score) of every analysis, for the distribution chart."""
    if not db_path.is_file():
        return []
    init_db(db_path)
    with connect(db_path) as conn:
        return [(r[0], r[1]) for r in conn.execute("SELECT verdict, risk_score FROM analyses")]


def top_signal_codes(db_path: Path, limit: int = 8) -> list[tuple[str, int]]:
    """Most frequent indicator codes across all analyses."""
    if not db_path.is_file():
        return []
    init_db(db_path)
    counter: Counter[str] = Counter()
    with connect(db_path) as conn:
        for (codes,) in conn.execute("SELECT signal_codes FROM analyses WHERE num_signals > 0"):
            counter.update(c for c in codes.split(",") if c)
    return counter.most_common(limit)


# --- History browsing (filters, search, deletion) -----------------------------

MAX_SEARCH_LENGTH = 100


@dataclass(frozen=True)
class HistoryFilter:
    """Criteria for browsing the history. Empty tuples mean "no restriction"."""

    verdicts: tuple[str, ...] = ()
    types: tuple[str, ...] = ()
    date_from: date | None = None  # inclusive, UTC day
    date_to: date | None = None  # inclusive, UTC day
    search: str = ""  # matched against target, ID and indicator codes


LIKE_ESCAPE = "!"


def _escape_like(text: str) -> str:
    """Escape LIKE wildcards so user input is matched literally (escape char: '!')."""
    return text.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def _where(f: HistoryFilter) -> tuple[str, list]:
    clauses: list[str] = []
    params: list = []
    verdicts = [v for v in f.verdicts if v in VERDICTS]
    if verdicts:
        clauses.append(f"verdict IN ({','.join('?' * len(verdicts))})")
        params += verdicts
    types = [t for t in f.types if t in TYPES]
    if types:
        clauses.append(f"analysis_type IN ({','.join('?' * len(types))})")
        params += types
    if f.date_from:
        clauses.append("substr(created_at, 1, 10) >= ?")
        params.append(f.date_from.isoformat())
    if f.date_to:
        clauses.append("substr(created_at, 1, 10) <= ?")
        params.append(f.date_to.isoformat())
    term = f.search.strip()[:MAX_SEARCH_LENGTH].lower()
    if term:
        like = f"%{_escape_like(term)}%"
        clauses.append(
            "(lower(target) LIKE ? ESCAPE '!' OR lower(public_id) LIKE ? ESCAPE '!' "
            "OR lower(signal_codes) LIKE ? ESCAPE '!')"
        )
        params += [like, like, like]
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def count_analyses(db_path: Path, f: HistoryFilter | None = None) -> int:
    if not db_path.is_file():
        return 0
    init_db(db_path)
    where, params = _where(f or HistoryFilter())
    with connect(db_path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM analyses{where}", params).fetchone()[0]  # noqa: S608


def list_analyses(
    db_path: Path, f: HistoryFilter | None = None, limit: int | None = None
) -> list[AnalysisRecord]:
    """Matching analyses, newest first. ``limit=None`` returns all of them."""
    if not db_path.is_file():
        return []
    init_db(db_path)
    where, params = _where(f or HistoryFilter())
    sql = f"SELECT * FROM analyses{where} ORDER BY created_at DESC, id DESC"  # noqa: S608
    if limit is not None:
        sql += " LIMIT ?"
        params.append(int(limit))
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_record(r) for r in rows]


def delete_analyses(db_path: Path, public_ids: list[str]) -> int:
    """Delete the given analyses; returns the number of rows removed."""
    ids = [i for i in public_ids if i]
    if not ids or not db_path.is_file():
        return 0
    with connect(db_path) as conn:
        cur = conn.execute(
            f"DELETE FROM analyses WHERE public_id IN ({','.join('?' * len(ids))})",  # noqa: S608
            ids,
        )
        return cur.rowcount


def delete_all_analyses(db_path: Path) -> int:
    """Erase the whole history; returns the number of rows removed."""
    if not db_path.is_file():
        return 0
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM analyses")
        removed = cur.rowcount
    with connect(db_path) as conn:
        conn.execute("VACUUM")  # really remove the data from the file
    return removed
