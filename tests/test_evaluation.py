"""Tests for the full-engine evaluation, the evaluation loader and the evaluation page.

A small synthetic corpus is used to exercise the code paths; its metrics mean nothing.
"""

import json

import pytest
from streamlit.testing.v1 import AppTest

from scripts.evaluate_engine import ENGINE_JSON, ENGINE_MD, EvaluationError, evaluate
from scripts.evaluate_engine import main as evaluate_main
from services.evaluation import load_evaluation
from tests.conftest import PROJECT_ROOT
from tests.test_train_predict import trained  # noqa: F401  (pytest fixture)


def test_engine_evaluation_end_to_end(trained):  # noqa: F811
    settings, meta = trained
    assert evaluate_main([]) == 0
    metrics = json.loads((settings.reports_dir / ENGINE_JSON).read_text(encoding="utf-8"))
    assert (settings.reports_dir / ENGINE_MD).is_file()
    assert metrics["model_version"] == meta["model_version"]
    assert metrics["n_test"] == meta["dataset"]["n_test"]
    matrix = metrics["verdict_matrix"]["matrix"]
    assert len(matrix) == 2 and all(len(r) == 3 for r in matrix)
    assert sum(map(sum, matrix)) == metrics["n_test"]
    for key in ("engine_phishing_verdict", "engine_flagged", "model_only_at_0_5"):
        assert 0.0 <= metrics[key]["precision"] <= 1.0
        assert 0.0 <= metrics[key]["false_positive_rate"] <= 1.0
    # "flagged" (suspect or phishing) always catches at least as much as "phishing" only
    assert metrics["engine_flagged"]["recall"] >= metrics["engine_phishing_verdict"]["recall"]


def test_engine_evaluation_detects_changed_dataset(trained):  # noqa: F811
    settings, _ = trained
    csv_path = settings.processed_data_dir / "emails.csv"
    csv_path.write_text(csv_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(EvaluationError, match="changed"):
        evaluate(settings)


def test_engine_evaluation_requires_split(trained):  # noqa: F811
    settings, _ = trained
    (settings.reports_dir / "test_split.json").unlink()
    with pytest.raises(EvaluationError, match="Retrain"):
        evaluate(settings)
    assert evaluate_main([]) == 1


def test_load_evaluation_states(trained):  # noqa: F811
    settings, meta = trained
    data = load_evaluation(settings)
    assert data.model["model_version"] == meta["model_version"]
    assert data.engine is None and not data.engine_stale

    evaluate_main([])
    assert load_evaluation(settings).engine is not None

    path = settings.reports_dir / ENGINE_JSON
    stale = json.loads(path.read_text(encoding="utf-8")) | {"model_version": "old"}
    path.write_text(json.dumps(stale), encoding="utf-8")
    data = load_evaluation(settings)
    assert data.engine is None and data.engine_stale

    path.write_text("{not json", encoding="utf-8")
    assert load_evaluation(settings).engine is None


def _page() -> AppTest:
    at = AppTest.from_file(str(PROJECT_ROOT / "app.py"), default_timeout=60)
    at.run()
    at.switch_page("pages/model_evaluation.py")
    at.run()
    assert not at.exception, at.exception
    return at


def test_evaluation_page_without_model(clean_env, tmp_path):
    clean_env.setenv("PHISHGUARD_MODELS_DIR", str(tmp_path / "models"))
    clean_env.setenv("PHISHGUARD_REPORTS_DIR", str(tmp_path / "reports"))
    at = _page()
    assert any("No trained model" in i.value for i in at.info)


def test_evaluation_page_with_model_and_engine(trained):  # noqa: F811
    at = _page()
    headings = " ".join(m.value for m in at.markdown)
    assert "AI model — held-out test set" in headings
    assert "Complete risk engine" in headings
    assert any("has not been evaluated" in i.value for i in at.info)

    evaluate_main([])
    at = _page()
    assert not any("has not been evaluated" in i.value for i in at.info)
    assert len(at.dataframe) >= 3  # comparison, engine metrics, sources
