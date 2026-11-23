"""Tests for history filtering, search, deletion and CSV reports."""

import csv
import io
import sqlite3
from datetime import UTC, date, datetime

import pytest

from database.repository import (
    HistoryFilter,
    count_analyses,
    delete_all_analyses,
    delete_analyses,
    get_stats,
    insert_analysis,
    list_analyses,
    top_signal_codes,
)
from services.reports import (
    HISTORY_COLUMNS,
    history_csv,
    neutralize_cell,
    result_csv,
    stats_csv,
)
from services.risk_engine import AnalysisResult, Verdict
from services.signals import Category, Signal


def _add(db, verdict, kind, target, codes=(), day=23):
    return insert_analysis(
        db,
        analysis_type=kind,
        verdict=verdict,
        risk_score={"phishing": 0.9, "suspect": 0.5, "legitimate": 0.1}[verdict],
        rule_score=0.3,
        ml_probability=None,
        model_version=None,
        target=target,
        signal_codes=list(codes),
        metadata={},
        duration_ms=1.0,
        created_at=datetime(2026, 11, day, 12, tzinfo=UTC),
    )


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "h.db"
    _add(path, "phishing", "email", "paypa1-support.example", ("content_urgency",), day=20)
    _add(path, "phishing", "url", "203.0.113.7", ("url_ip_host",), day=21)
    _add(path, "suspect", "url", "login_verify.example", ("url_keywords",), day=22)
    _add(path, "legitimate", "email", "colleague.example", (), day=23)
    return path


def _csv_rows(data: bytes) -> list[list[str]]:
    assert data.startswith("﻿".encode())  # BOM for Excel
    return list(csv.reader(io.StringIO(data.decode("utf-8-sig"))))


# --- Filters -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flt", "expected"),
    [
        (HistoryFilter(), 4),
        (HistoryFilter(verdicts=("phishing",)), 2),
        (HistoryFilter(verdicts=("phishing", "suspect")), 3),
        (HistoryFilter(types=("url",)), 2),
        (HistoryFilter(verdicts=("phishing",), types=("email",)), 1),
        (HistoryFilter(date_from=date(2026, 11, 22)), 2),
        (HistoryFilter(date_to=date(2026, 11, 20)), 1),
        (HistoryFilter(date_from=date(2026, 11, 21), date_to=date(2026, 11, 22)), 2),
        (HistoryFilter(search="PAYPA1"), 1),  # case-insensitive, matches target
        (HistoryFilter(search="urgency"), 1),  # matches indicator code
        (HistoryFilter(search="203.0.113"), 1),
        (HistoryFilter(verdicts=("bogus",)), 4),  # unknown values are ignored
    ],
)
def test_filters(db, flt, expected):
    assert count_analyses(db, flt) == expected
    assert len(list_analyses(db, flt)) == expected


def test_search_wildcards_are_literal(db):
    # "_" and "%" must not act as SQL LIKE wildcards
    assert count_analyses(db, HistoryFilter(search="login_verify")) == 1
    assert count_analyses(db, HistoryFilter(search="login_")) == 1
    assert count_analyses(db, HistoryFilter(search="%")) == 0
    # A literal "_" matches the 3 records whose target or indicator codes contain one
    # (as a wildcard it would also match the 4th record, "colleague.example").
    assert count_analyses(db, HistoryFilter(search="_")) == 3
    assert count_analyses(db, HistoryFilter(search="!")) == 0


def test_search_injection_attempt_is_harmless(db):
    assert count_analyses(db, HistoryFilter(search="' OR 1=1 --")) == 0
    assert get_stats(db).total == 4


def test_search_by_id(db):
    record = list_analyses(db)[0]
    assert list_analyses(db, HistoryFilter(search=record.public_id))[0] == record


def test_list_is_newest_first_and_limited(db):
    rows = list_analyses(db, limit=2)
    assert [r.target for r in rows] == ["colleague.example", "login_verify.example"]


# --- Deletion ------------------------------------------------------------------


def test_delete_selected(db):
    ids = [r.public_id for r in list_analyses(db, HistoryFilter(verdicts=("phishing",)))]
    assert delete_analyses(db, ids) == 2
    assert get_stats(db).by_verdict["phishing"] == 0
    assert get_stats(db).total == 2
    assert delete_analyses(db, ["does-not-exist"]) == 0
    assert delete_analyses(db, []) == 0


def test_delete_all(db):
    assert delete_all_analyses(db) == 4
    assert get_stats(db).total == 0
    with sqlite3.connect(db) as conn:  # schema still usable afterwards
        assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0


def test_delete_on_missing_db(tmp_path):
    assert delete_all_analyses(tmp_path / "none.db") == 0
    assert delete_analyses(tmp_path / "none.db", ["x"]) == 0
    assert not (tmp_path / "none.db").exists()


# --- CSV reports ---------------------------------------------------------------


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"])
def test_neutralize_formula_cells(value):
    assert neutralize_cell(value) == "'" + value


def test_neutralize_keeps_safe_values():
    assert neutralize_cell("example.com") == "example.com"
    assert neutralize_cell(0.5) == 0.5
    assert neutralize_cell(None) is None


def test_history_csv(db):
    rows = _csv_rows(history_csv(list_analyses(db)))
    assert rows[0] == HISTORY_COLUMNS
    assert len(rows) == 5
    first = dict(zip(rows[0], rows[1], strict=True))
    assert first["verdict_label"] == "Likely legitimate"
    url_row = next(dict(zip(rows[0], r, strict=True)) for r in rows[1:] if r[2] == "url")
    assert url_row["indicators"] in {"IP address instead of domain", "Sensitive keywords in URL"}


def test_history_csv_neutralizes_malicious_target(tmp_path):
    path = tmp_path / "h.db"
    _add(path, "phishing", "url", '=HYPERLINK("http://evil.example")')
    rows = _csv_rows(history_csv(list_analyses(path)))
    target = dict(zip(rows[0], rows[1], strict=True))["target"]
    assert target.startswith("'=")


def test_history_csv_empty_has_header():
    assert _csv_rows(history_csv([])) == [HISTORY_COLUMNS]


def test_stats_csv(db):
    rows = dict(_csv_rows(stats_csv(get_stats(db), top_signal_codes(db)))[1:])
    assert rows["total_analyses"] == "4"
    assert rows["verdict_phishing"] == "2"
    assert rows["verdict_phishing_share"] == "0.5"
    assert rows["indicator: Urgency"] == "1"


def test_result_csv():
    result = AnalysisResult(
        analysis_type="email",
        verdict=Verdict.PHISHING,
        risk_score=0.82,
        rule_score=0.7,
        ml_probability=0.9,
        signals=[Signal("content_urgency", Category.CONTENT, "Urgent", "-Found: now", 0.2)],
        ml_terms=["verify [link]"],
        recommendations=["Do not click."],
    )
    rows = _csv_rows(result_csv(result, "abc123", "mail.example"))
    assert rows[0] == ["section", "field", "value"]
    summary = {r[1]: r[2] for r in rows if r[0] == "summary"}
    assert summary["verdict"] == "Likely phishing"
    assert summary["target"] == "mail.example"
    sections = [r[0] for r in rows[1:]]
    assert {"indicator", "ai_terms", "recommendation", "disclaimer"} <= set(sections)
