"""Tests for the SQLite history layer and the history service."""

import sqlite3
from datetime import UTC, date, datetime, timedelta

import pytest

from config.settings import load_settings
from database.repository import (
    daily_activity,
    get_stats,
    insert_analysis,
    recent_analyses,
    risk_scores,
    top_signal_codes,
)
from services.history import record_analysis
from services.risk_engine import AnalysisResult, Verdict


def _insert(db, verdict="phishing", kind="email", score=0.8, codes=("content_urgency",), **kw):
    return insert_analysis(
        db,
        analysis_type=kind,
        verdict=verdict,
        risk_score=score,
        rule_score=score,
        ml_probability=None,
        model_version=None,
        target=kw.pop("target", "example.org"),
        signal_codes=list(codes),
        metadata={"num_urls": 1},
        duration_ms=3.0,
        **kw,
    )


def test_missing_db_gives_empty_results_without_creating_file(tmp_path):
    db = tmp_path / "h.db"
    stats = get_stats(db)
    assert stats.total == 0 and stats.average_risk is None
    assert recent_analyses(db) == [] and risk_scores(db) == [] and top_signal_codes(db) == []
    assert daily_activity(db, days=7)["count"].sum() == 0
    assert not db.exists()


def test_insert_and_stats(tmp_path):
    db = tmp_path / "h.db"
    _insert(db, "phishing", "email", 0.9)
    _insert(db, "suspect", "url", 0.5, codes=("url_no_https", "url_keywords"))
    _insert(db, "legitimate", "email", 0.1, codes=())
    s = get_stats(db)
    assert s.total == 3
    assert s.by_verdict == {"legitimate": 1, "suspect": 1, "phishing": 1}
    assert s.by_type == {"email": 2, "url": 1}
    assert s.average_risk == pytest.approx(0.5)
    assert sorted(v for v, _ in risk_scores(db)) == ["legitimate", "phishing", "suspect"]
    assert dict(top_signal_codes(db)) == {
        "content_urgency": 1,
        "url_no_https": 1,
        "url_keywords": 1,
    }


def test_recent_is_newest_first_and_parses(tmp_path):
    db = tmp_path / "h.db"
    old = datetime(2026, 1, 1, tzinfo=UTC)
    _insert(db, created_at=old, target="old.example")
    new_id = _insert(db, target="new.example")
    rows = recent_analyses(db, limit=5)
    assert [r.public_id for r in rows][0] == new_id
    assert rows[0].signal_codes == ("content_urgency",)
    assert rows[0].metadata == {"num_urls": 1}
    assert rows[1].created_at == old


def test_daily_activity_zero_filled(tmp_path):
    db = tmp_path / "h.db"
    today = date(2026, 11, 23)
    _insert(db, "phishing", created_at=datetime(2026, 11, 23, 9, tzinfo=UTC))
    _insert(db, "phishing", created_at=datetime(2026, 11, 23, 10, tzinfo=UTC))
    _insert(db, "legitimate", created_at=datetime(2026, 11, 21, 10, tzinfo=UTC))
    _insert(db, "legitimate", created_at=datetime(2026, 10, 1, tzinfo=UTC))  # out of window
    df = daily_activity(db, days=7, today=today)
    assert len(df) == 7 * 3
    by = df.set_index(["day", "verdict"])["count"]
    assert by[(today, "phishing")] == 2
    assert by[(today - timedelta(days=2), "legitimate")] == 1
    assert df["count"].sum() == 3


def test_invalid_values_rejected(tmp_path):
    db = tmp_path / "h.db"
    with pytest.raises(ValueError):
        _insert(db, verdict="safe")
    with pytest.raises(ValueError):
        _insert(db, kind="sms")
    with pytest.raises(sqlite3.IntegrityError):
        _insert(db, score=1.5)  # CHECK constraint


def test_sql_injection_is_stored_as_text(tmp_path):
    db = tmp_path / "h.db"
    payload = "x'); DROP TABLE analyses; --"
    _insert(db, target=payload)
    assert recent_analyses(db)[0].target == payload
    assert get_stats(db).total == 1


# --- history service ---


def _result(kind="email"):
    return AnalysisResult(
        analysis_type=kind,
        verdict=Verdict.SUSPECT,
        risk_score=0.5,
        rule_score=0.3,
        ml_probability=0.7 if kind == "email" else None,
        signals=[],
        metadata={"sender_domain": "mail.example", "host": "site.example"},
    )


@pytest.mark.parametrize("store", [False, True])
def test_record_analysis_privacy_flag(clean_env, tmp_path, store):
    clean_env.setenv("PHISHGUARD_DB_PATH", str(tmp_path / "h.db"))
    clean_env.setenv("PHISHGUARD_STORE_EMAIL_BODY", "true" if store else "false")
    settings = load_settings()
    assert record_analysis(_result(), settings, raw_text="secret body") is not None
    with sqlite3.connect(settings.db_path) as conn:
        content, target = conn.execute("SELECT content, target FROM analyses").fetchone()
    assert target == "mail.example"
    assert content == ("secret body" if store else None)


def test_record_url_target_is_host(clean_env, tmp_path):
    clean_env.setenv("PHISHGUARD_DB_PATH", str(tmp_path / "h.db"))
    settings = load_settings()
    record_analysis(_result("url"), settings, raw_text="ignored")
    assert recent_analyses(settings.db_path)[0].target == "site.example"


def test_record_analysis_failure_returns_none(clean_env, tmp_path):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    clean_env.setenv("PHISHGUARD_DB_PATH", str(blocker / "h.db"))
    assert record_analysis(_result(), load_settings()) is None
