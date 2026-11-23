"""Tests for the platform status checks shown on the home page."""

from services.system_status import (
    collect_status,
    database_status,
    dataset_status,
    model_status,
)


def test_everything_missing_in_empty_environment(tmp_settings):
    statuses = collect_status(tmp_settings)
    assert [s.name for s in statuses] == ["Datasets", "ML model", "Analysis history"]
    assert all(not s.available for s in statuses)
    assert all(s.next_step for s in statuses)


def test_dataset_requires_both_corpora(tmp_settings):
    spam_dir = tmp_settings.raw_data_dir / "spamassassin" / "easy_ham"
    spam_dir.mkdir(parents=True)
    (spam_dir / "00001.msg").write_text("hello", encoding="utf-8")
    assert not dataset_status(tmp_settings).available

    nazario_dir = tmp_settings.raw_data_dir / "nazario"
    nazario_dir.mkdir(parents=True)
    (nazario_dir / "phishing-2023.mbox").write_text("From x", encoding="utf-8")
    status = dataset_status(tmp_settings)
    assert status.available
    assert "SpamAssassin: 1 files" in status.detail


def test_model_requires_metadata(tmp_settings):
    tmp_settings.models_dir.mkdir(parents=True)
    tmp_settings.model_path.write_bytes(b"x")
    assert not model_status(tmp_settings).available
    tmp_settings.model_metadata_path.write_text("{}", encoding="utf-8")
    assert model_status(tmp_settings).available


def test_database_detected(tmp_settings):
    tmp_settings.db_path.parent.mkdir(parents=True)
    tmp_settings.db_path.write_bytes(b"")
    assert database_status(tmp_settings).available
