"""End-to-end test of training, saving, loading and predicting on a synthetic corpus.

These tests check that the pipeline WORKS (files, shapes, ranges, integrity),
not how accurate it is: metrics on synthetic data are meaningless.
"""

import json

import pytest

from config.settings import load_settings
from ml.predict import ModelNotAvailableError, PhishingClassifier
from ml.train import train
from scripts.prepare_data import main as prepare_main
from tests.sample_corpus import write_sample_corpus


@pytest.fixture
def trained(clean_env, tmp_path):
    clean_env.setenv("PHISHGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_env.setenv("PHISHGUARD_MODELS_DIR", str(tmp_path / "models"))
    clean_env.setenv("PHISHGUARD_REPORTS_DIR", str(tmp_path / "reports"))
    settings = load_settings()
    write_sample_corpus(settings.raw_data_dir, n_ham=40, n_phish=40)
    assert prepare_main([]) == 0
    metadata = train(
        settings, settings.processed_data_dir / "emails.csv", cv_folds=3, verbose=False
    )
    return settings, metadata


def test_training_writes_artifacts(trained):
    settings, meta = trained
    assert settings.model_path.is_file()
    assert settings.model_metadata_path.is_file()
    assert (settings.reports_dir / "evaluation_report.md").is_file()
    saved = json.loads(settings.model_metadata_path.read_text(encoding="utf-8"))
    assert saved["model_sha256"]
    assert saved["model_name"] in {"naive_bayes", "linear_svm"}
    assert set(saved["selection"]["cv_results"]) == {"naive_bayes", "linear_svm"}


def test_split_is_stratified_and_disjoint(trained):
    _, meta = trained
    ds = meta["dataset"]
    assert ds["n_train"] + ds["n_test"] == ds["n_total"] == 80
    # group split: stratification is approximate, but both classes must be in test
    assert ds["test_class_counts"]["legitimate"] > 0
    assert ds["test_class_counts"]["phishing"] > 0
    # no subject (campaign) appears on both sides of the split
    assert meta["split"]["test_subject_overlap_rate"] == 0.0


def test_metrics_are_well_formed(trained):
    _, meta = trained
    m = meta["test_metrics"]
    for key in ("precision_phishing", "recall_phishing", "f1_phishing", "roc_auc", "accuracy"):
        assert 0.0 <= m[key] <= 1.0
    cm = m["confusion_matrix"]
    assert sum(sum(r) for r in cm["matrix"]) == meta["dataset"]["n_test"]
    assert len(m["roc_curve"]["fpr"]) == len(m["roc_curve"]["tpr"])


def test_predict_and_explain(trained):
    settings, _ = trained
    model = PhishingClassifier.load(settings.model_path, settings.model_metadata_path)
    pred = model.predict("Urgent: account suspended", "Verify your password immediately here")
    assert 0.0 <= pred.probability <= 1.0
    assert pred.label_name in {"legitimate", "phishing"}
    terms = model.explain("Urgent: account suspended", "Verify your password immediately")
    assert all(weight > 0 for _, weight in terms)
    assert model.version != "unknown"


def test_load_rejects_tampered_model(trained):
    settings, _ = trained
    with settings.model_path.open("ab") as handle:
        handle.write(b"tampered")
    with pytest.raises(ModelNotAvailableError, match="integrity"):
        PhishingClassifier.load(settings.model_path, settings.model_metadata_path)


def test_load_missing_model(tmp_path):
    with pytest.raises(ModelNotAvailableError, match="No trained model"):
        PhishingClassifier.load(tmp_path / "m.joblib", tmp_path / "m.json")
