"""Tests for corpus loading, deduplication and processed-CSV validation."""

import pandas as pd
import pytest

from ml.dataset import DatasetError, build_dataset, load_processed
from scripts.prepare_data import main as prepare_main
from tests.sample_corpus import write_sample_corpus


def test_build_dataset_labels_and_ignores_spam(tmp_path):
    write_sample_corpus(tmp_path, n_ham=12, n_phish=10)
    df, stats = build_dataset(tmp_path)
    assert stats.final_by_label == {"legitimate": 12, "phishing": 10}
    assert set(df["source"]) == {"spamassassin_easy_ham", "nazario"}
    assert "spamassassin_spam" not in stats.raw_by_source  # spam folder ignored
    assert df["id"].is_unique
    assert (df.loc[df["source"] == "nazario", "label"] == 1).all()


def test_duplicates_removed_before_split(tmp_path):
    write_sample_corpus(tmp_path, n_ham=5, n_phish=5)
    easy = tmp_path / "spamassassin" / "easy_ham"
    # Same text, different whitespace/case and a different number -> same fingerprint
    (easy / "dup1").write_text("Subject: Hello\n\nMeeting at 10 in ROOM 4", encoding="utf-8")
    (easy / "dup2").write_text("Subject: hello\n\nmeeting at 11   in room 7", encoding="utf-8")
    df, stats = build_dataset(tmp_path)
    assert stats.duplicates_removed == 1
    assert stats.final_by_label["legitimate"] == 6


def test_missing_folders_raise(tmp_path):
    with pytest.raises(DatasetError, match="Missing dataset folder"):
        build_dataset(tmp_path)


def test_prepare_script_writes_csv(tmp_path, capsys):
    raw, out = tmp_path / "raw", tmp_path / "processed"
    write_sample_corpus(raw, n_ham=12, n_phish=12)
    assert prepare_main(["--raw-dir", str(raw), "--out-dir", str(out)]) == 0
    df = load_processed(out / "emails.csv")
    assert len(df) == 24
    assert (out / "dataset_stats.json").is_file()
    assert "Final dataset" in capsys.readouterr().out


def test_prepare_script_reports_missing_data(tmp_path, capsys):
    assert prepare_main(["--raw-dir", str(tmp_path), "--out-dir", str(tmp_path / "o")]) == 1
    assert "data/README.md" in capsys.readouterr().err


def _csv(tmp_path, rows):
    path = tmp_path / "emails.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_load_processed_validation(tmp_path):
    with pytest.raises(DatasetError, match="not found"):
        load_processed(tmp_path / "nope.csv")

    with pytest.raises(DatasetError, match="missing columns"):
        load_processed(_csv(tmp_path, [{"id": "a", "label": 0}]))

    base = {"source": "s", "subject": "x", "body": "y"}
    bad_label = [{**base, "id": str(i), "label": 2} for i in range(3)]
    with pytest.raises(DatasetError, match="Labels"):
        load_processed(_csv(tmp_path, bad_label), min_per_class=1)

    one_class = [{**base, "id": str(i), "label": 0} for i in range(20)]
    with pytest.raises(DatasetError, match="phishing"):
        load_processed(_csv(tmp_path, one_class))
