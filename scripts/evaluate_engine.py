"""Evaluate the COMPLETE risk engine (AI model + rules) on the held-out test set.

Usage::

    python -m scripts.evaluate_engine

ml/train.py measures the AI model alone. The application, however, shows the
verdict of the combined engine (services/risk_engine.py). This script runs the
same scoring as the app on exactly the test emails the model never saw during
training, and reports what users actually get.

Writes reports/engine_metrics.json and reports/engine_evaluation.md.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from config.settings import Settings, get_settings
from ml.dataset import DatasetError, load_processed
from ml.predict import ModelNotAvailableError, PhishingClassifier, file_sha256
from ml.train import PROCESSED_CSV, TEST_SPLIT_FILE
from services.email_analyzer import analyze_email
from services.risk_engine import combine_email_score, verdict_for

ENGINE_JSON = "engine_metrics.json"
ENGINE_MD = "engine_evaluation.md"
VERDICTS = ("legitimate", "suspect", "phishing")

SCOPE_NOTE = (
    "The processed dataset keeps only the subject and body (headers and attachments are "
    "removed to avoid leakage), so sender-spoofing and attachment indicators cannot fire "
    "here: the rules are evaluated on content and link indicators only."
)


class EvaluationError(RuntimeError):
    pass


def _binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(
            ((y_pred == 1) & (y_true == 0)).sum() / max(1, (y_true == 0).sum())
        ),
    }


def evaluate(settings: Settings) -> dict:
    split_path = settings.reports_dir / TEST_SPLIT_FILE
    if not split_path.is_file():
        raise EvaluationError(f"{split_path} not found. Retrain with: python -m ml.train")
    split = json.loads(split_path.read_text(encoding="utf-8"))
    classifier = PhishingClassifier.load(settings.model_path, settings.model_metadata_path)
    if split["model_version"] != classifier.version:
        raise EvaluationError("The saved test split belongs to another model. Retrain the model.")
    csv_path = settings.processed_data_dir / PROCESSED_CSV
    df = load_processed(csv_path)
    if file_sha256(csv_path) != split["dataset_sha256"]:
        raise EvaluationError("The processed dataset changed since training. Retrain the model.")

    test = df[df["id"].astype(str).isin(set(split["test_ids"]))]
    if len(test) != len(split["test_ids"]):
        raise EvaluationError("Some test emails are missing from the dataset. Retrain the model.")

    start = time.perf_counter()
    y_true, ml_probs, rule_scores, scores, verdicts = [], [], [], [], []
    for subject, body, label in zip(test["subject"], test["body"], test["label"], strict=True):
        analysis = analyze_email(body, subject=subject)
        p = classifier.predict(analysis.content.subject, analysis.content.body).probability
        rules = analysis.rule_score
        score = combine_email_score(p, rules, settings.ml_weight)
        y_true.append(int(label))
        ml_probs.append(p)
        rule_scores.append(rules)
        scores.append(score)
        verdicts.append(verdict_for(score, settings).value)
    elapsed = time.perf_counter() - start

    y = np.array(y_true)
    verdict_arr = np.array(verdicts)
    cm = confusion_matrix(
        np.where(y == 1, "phishing", "legitimate"),
        verdict_arr,
        labels=["legitimate", "suspect", "phishing"],
    )[[0, 2]]  # rows: true legitimate, true phishing ; columns: 3 verdicts

    metrics = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "model_version": classifier.version,
        "n_test": len(y),
        "settings": {
            "ml_weight": settings.ml_weight,
            "suspect_threshold": settings.suspect_threshold,
            "phishing_threshold": settings.phishing_threshold,
        },
        "verdict_matrix": {
            "rows": ["true legitimate", "true phishing"],
            "columns": list(VERDICTS),
            "matrix": cm.tolist(),
        },
        "engine_phishing_verdict": _binary_metrics(y, (verdict_arr == "phishing").astype(int)),
        "engine_flagged": _binary_metrics(y, (verdict_arr != "legitimate").astype(int)),
        "model_only_at_0_5": _binary_metrics(y, (np.array(ml_probs) >= 0.5).astype(int)),
        "roc_auc": {
            "engine_score": float(roc_auc_score(y, scores)),
            "model_probability": float(roc_auc_score(y, ml_probs)),
            "rule_score": float(roc_auc_score(y, rule_scores)),
        },
        "mean_rule_score": {
            "legitimate": float(np.mean(np.array(rule_scores)[y == 0])),
            "phishing": float(np.mean(np.array(rule_scores)[y == 1])),
        },
        "seconds_per_email": elapsed / max(1, len(y)),
        "scope_note": SCOPE_NOTE,
    }
    return metrics


def write_markdown(path: Path, m: dict) -> None:
    rows = m["verdict_matrix"]["matrix"]
    lines = [
        "# PhishGuard AI — Full risk engine evaluation",
        "",
        f"- Model version: `{m['model_version']}` · evaluated {m['generated_at']}",
        f"- Held-out test emails: {m['n_test']} (never seen during training)",
        f"- Settings: ML weight {m['settings']['ml_weight']}, Suspicious ≥ "
        f"{m['settings']['suspect_threshold']}, Likely phishing ≥ "
        f"{m['settings']['phishing_threshold']}",
        "",
        "## Verdicts given by the application",
        "",
        "| True class | ✔ Likely legitimate | ⚠ Suspicious | ✖ Likely phishing |",
        "|---|---|---|---|",
        f"| Legitimate | {rows[0][0]} | {rows[0][1]} | {rows[0][2]} |",
        f"| Phishing | {rows[1][0]} | {rows[1][1]} | {rows[1][2]} |",
        "",
        "## Detection metrics (phishing = positive class)",
        "",
        "| Decision rule | Precision | Recall | F1 | False-positive rate |",
        "|---|---|---|---|---|",
    ]
    for key, label in (
        ("engine_phishing_verdict", "Engine: verdict = Likely phishing"),
        ("engine_flagged", "Engine: verdict = Suspicious or Likely phishing"),
        ("model_only_at_0_5", "AI model alone (probability ≥ 0.5)"),
    ):
        x = m[key]
        lines.append(
            f"| {label} | {x['precision']:.4f} | {x['recall']:.4f} | {x['f1']:.4f} "
            f"| {x['false_positive_rate']:.4f} |"
        )
    r = m["roc_auc"]
    lines += [
        "",
        f"ROC-AUC — engine score {r['engine_score']:.4f}, AI probability "
        f"{r['model_probability']:.4f}, rule score alone {r['rule_score']:.4f}.",
        "",
        f"Mean rule score — legitimate {m['mean_rule_score']['legitimate']:.3f}, "
        f"phishing {m['mean_rule_score']['phishing']:.3f}.",
        "",
        f"Average analysis time: {m['seconds_per_email'] * 1000:.1f} ms per email.",
        "",
        "## Scope",
        "",
        f"- {m['scope_note']}",
        "- The engine deliberately needs concrete indicators to say *Likely phishing*, so it "
        "trades recall on the 'Likely phishing' verdict for fewer false alarms; emails the "
        "model finds suspicious without indicators land in *Suspicious*.",
        "- Same corpus limitations as the model evaluation report apply.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    try:
        metrics = evaluate(settings)
    except (EvaluationError, ModelNotAvailableError, DatasetError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    (settings.reports_dir / ENGINE_JSON).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    write_markdown(settings.reports_dir / ENGINE_MD, metrics)
    for key in ("engine_phishing_verdict", "engine_flagged", "model_only_at_0_5"):
        x = metrics[key]
        print(f"{key:<26} P={x['precision']:.4f} R={x['recall']:.4f} F1={x['f1']:.4f} "
              f"FPR={x['false_positive_rate']:.4f}")  # fmt: skip
    print(f"Verdict matrix (rows true legit/phish; cols legit/suspect/phish): "
          f"{metrics['verdict_matrix']['matrix']}")  # fmt: skip
    print(f"Written: {settings.reports_dir / ENGINE_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
