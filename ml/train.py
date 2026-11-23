"""Train, compare, evaluate and save the phishing email classifier.

Usage::

    python -m ml.train

Method (anti-leakage by design)
-------------------------------
1. Load ``data/processed/emails.csv`` (already deduplicated *before* splitting).
2. Stratified, seeded train/test split.
3. Candidate pipelines (TF-IDF + Naive Bayes, TF-IDF + calibrated linear SVM)
   are compared by stratified k-fold cross-validation **on the training set only**.
   The test set is never used to choose the model.
4. The selected pipeline is refitted on the whole training set and evaluated
   once on the held-out test set. TF-IDF is fitted inside the pipeline, so it
   never sees test data.
5. The model, its metadata and an evaluation report are written to disk.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedGroupKFold, cross_validate
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from config.settings import Settings, get_settings
from ml.dataset import LABEL_NAMES, LABEL_PHISHING, DatasetError, load_processed
from ml.predict import DECISION_THRESHOLD, feature_weights, file_sha256
from ml.preprocess import build_model_text, normalize_text

PROCESSED_CSV = "emails.csv"
TEST_SPLIT_FILE = "test_split.json"

ALGORITHM_LABELS = {
    "naive_bayes": "TF-IDF + Multinomial Naive Bayes",
    "linear_svm": "TF-IDF + Linear SVM (sigmoid-calibrated)",
}


# --- Model definitions -------------------------------------------------------


def _vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        preprocessor=normalize_text,
        strip_accents="unicode",
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        max_features=50_000,
        sublinear_tf=True,
    )


def build_candidates(seed: int) -> dict[str, Pipeline]:
    """Return the candidate pipelines, keyed by short name."""
    return {
        "naive_bayes": Pipeline([("tfidf", _vectorizer()), ("clf", MultinomialNB(alpha=0.1))]),
        "linear_svm": Pipeline(
            [
                ("tfidf", _vectorizer()),
                (
                    "clf",
                    CalibratedClassifierCV(
                        LinearSVC(C=1.0, class_weight="balanced", random_state=seed),
                        method="sigmoid",
                        cv=3,
                    ),
                ),
            ]
        ),
    }


# --- Metrics -------------------------------------------------------------------


def compute_metrics(y_true: np.ndarray, proba: np.ndarray) -> dict:
    """Compute test-set metrics. The phishing class (1) is the positive class."""
    y_pred = (proba >= DECISION_THRESHOLD).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fpr, tpr, _ = roc_curve(y_true, proba)
    step = max(1, len(fpr) // 200)  # keep the stored curve small
    report = classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=[LABEL_NAMES[0], LABEL_NAMES[1]],
        output_dict=True,
        zero_division=0,
    )
    return {
        "decision_threshold": DECISION_THRESHOLD,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_phishing": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall_phishing": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_phishing": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, proba)),
        "average_precision": float(average_precision_score(y_true, proba)),
        "confusion_matrix": {
            "labels": [LABEL_NAMES[0], LABEL_NAMES[1]],
            "matrix": cm.tolist(),  # rows = true class, columns = predicted class
            "true_negative": int(cm[0, 0]),
            "false_positive": int(cm[0, 1]),
            "false_negative": int(cm[1, 0]),
            "true_positive": int(cm[1, 1]),
        },
        "per_class": {
            name: {k: float(v) for k, v in report[name].items()}
            for name in (LABEL_NAMES[0], LABEL_NAMES[1])
        },
        "roc_curve": {
            "fpr": [round(float(x), 5) for x in fpr[::step]] + [1.0],
            "tpr": [round(float(x), 5) for x in tpr[::step]] + [1.0],
        },
    }


def campaign_groups(df: pd.DataFrame) -> np.ndarray:
    """Group id per email: the normalised subject, a rough proxy for a campaign/thread.

    Emails sharing a subject (same phishing campaign, same mailing-list thread)
    are kept on the same side of every split. Emails without a subject form
    their own group.
    """
    subjects = [normalize_text(s) for s in df["subject"]]
    return np.array([f"s:{s}" if s else f"id:{i}" for s, i in zip(subjects, df["id"], strict=True)])


def group_train_test_split(
    y: np.ndarray, groups: np.ndarray, test_size: float, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    """Stratified split where no group appears in both train and test."""
    n_splits = max(2, round(1 / test_size))
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    idx_train, idx_test = next(splitter.split(np.zeros(len(y)), y, groups))
    return idx_train, idx_test


def subject_overlap_rate(train: pd.DataFrame, test: pd.DataFrame) -> float:
    """Share of test emails whose (non-empty) normalised subject also appears in train.

    Exact duplicates are already removed; this diagnostic estimates how many
    *near*-duplicates (same campaign, slightly different body) remain.
    """
    train_subjects = {normalize_text(s) for s in train["subject"] if normalize_text(s)}
    test_subjects = [normalize_text(s) for s in test["subject"]]
    non_empty = [s for s in test_subjects if s]
    if not non_empty:
        return 0.0
    return sum(s in train_subjects for s in non_empty) / len(non_empty)


def top_features(pipeline: Pipeline, n: int = 25) -> dict[str, list[str]]:
    terms = pipeline.named_steps["tfidf"].get_feature_names_out()
    weights = feature_weights(pipeline)
    order = np.argsort(weights)
    return {
        "phishing": [str(terms[i]) for i in order[::-1][:n]],
        "legitimate": [str(terms[i]) for i in order[:n]],
    }


# --- Persistence -----------------------------------------------------------


def _atomic_write_bytes_via(path: Path, writer) -> None:
    """Write to a temp file in the same folder, then atomically replace ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        writer(tmp)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _write_json(path: Path, data: dict) -> None:
    _atomic_write_bytes_via(
        path, lambda p: p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    )


def write_report(path: Path, meta: dict) -> None:
    """Human-readable evaluation report (deliverable L5)."""
    m = meta["test_metrics"]
    cm = m["confusion_matrix"]
    ds = meta["dataset"]
    lines = [
        "# PhishGuard AI — Model evaluation report",
        "",
        f"- **Model version:** `{meta['model_version']}`",
        f"- **Algorithm:** {meta['algorithm']}",
        f"- **Trained at (UTC):** {meta['created_at']}",
        f"- **scikit-learn:** {meta['environment']['sklearn_version']}",
        "",
        "## Dataset",
        "",
        f"- Sources: {', '.join(f'{k} ({v})' for k, v in ds['by_source'].items())}",
        f"- Total after deduplication: {ds['n_total']} "
        f"(legitimate {ds['class_counts']['legitimate']}, "
        f"phishing {ds['class_counts']['phishing']})",
        f"- Train / test: {ds['n_train']} / {ds['n_test']}",
        f"- Split: {meta['split']['method']}, test size {meta['split']['test_size']}, "
        f"seed {meta['split']['random_seed']}",
        f"- Test emails whose subject also appears in train (near-duplicate indicator): "
        f"{meta['split']['test_subject_overlap_rate']:.1%}",
        "",
        "## Model selection (cross-validation on the training set only)",
        "",
        "| Model | CV F1 (mean ± std) | CV precision | CV recall |",
        "|---|---|---|---|",
    ]
    for name, cv in meta["selection"]["cv_results"].items():
        lines.append(
            f"| {ALGORITHM_LABELS[name]} | {cv['f1_mean']:.4f} ± {cv['f1_std']:.4f} "
            f"| {cv['precision_mean']:.4f} | {cv['recall_mean']:.4f} |"
        )
    lines += [
        "",
        f"Selected: **{ALGORITHM_LABELS[meta['model_name']]}** (highest mean CV F1).",
        "",
        f"## Held-out test set results (threshold {m['decision_threshold']})",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Precision (phishing) | {m['precision_phishing']:.4f} |",
        f"| Recall (phishing) | {m['recall_phishing']:.4f} |",
        f"| F1-score (phishing) | {m['f1_phishing']:.4f} |",
        f"| Accuracy | {m['accuracy']:.4f} |",
        f"| ROC-AUC | {m['roc_auc']:.4f} |",
        f"| Average precision | {m['average_precision']:.4f} |",
        "",
        "Confusion matrix (rows = true class, columns = predicted class):",
        "",
        "| | Predicted legitimate | Predicted phishing |",
        "|---|---|---|",
        f"| **True legitimate** | {cm['true_negative']} | {cm['false_positive']} |",
        f"| **True phishing** | {cm['false_negative']} | {cm['true_positive']} |",
        "",
        "## Test-set results of every candidate (for comparison only, not for selection)",
        "",
        "| Model | Precision | Recall | F1 | ROC-AUC |",
        "|---|---|---|---|---|",
    ]
    for name, cm_ in meta["comparison_test_metrics"].items():
        lines.append(
            f"| {ALGORITHM_LABELS[name]} | {cm_['precision_phishing']:.4f} "
            f"| {cm_['recall_phishing']:.4f} | {cm_['f1_phishing']:.4f} | {cm_['roc_auc']:.4f} |"
        )
    lines += [
        "",
        "## Most influential terms",
        "",
        f"- Towards phishing: {', '.join(meta['top_features']['phishing'])}",
        f"- Towards legitimate: {', '.join(meta['top_features']['legitimate'])}",
        "",
        "## Known limitations",
        "",
        *[f"- {item}" for item in meta["limitations"]],
        "",
    ]
    _atomic_write_bytes_via(path, lambda p: p.write_text("\n".join(lines), encoding="utf-8"))


LIMITATIONS = [
    "Legitimate and phishing emails come from different corpora, periods and collection "
    "methods; part of the measured performance may reflect these differences rather than "
    "phishing itself. Known collection artifacts (collector address/domain, mailing-list "
    "footers, RSS gateway lines) are removed, but topic differences remain: the legitimate "
    "class is dominated by early-2000s tech mailing lists (Linux, RPM, SpamAssassin).",
    "SpamAssassin ham dates from around 2002-2005; current legitimate emails (e.g. modern "
    "transactional emails from banks or online shops) are under-represented, so false "
    "positives on such emails are likely to be higher than the test set suggests.",
    "Emails sharing a subject are kept on the same side of the split to limit campaign "
    "leakage, but near-duplicates with different subjects can still cross the split.",
    "Recent phishing samples include 'hash-busting' filler text (e.g. novel excerpts) whose "
    "words the model may associate with phishing.",
    "Test-set metrics describe performance on these corpora only, not guaranteed real-world "
    "detection on today's emails.",
    "The probability is a model estimate, not a certainty. A low score never proves an email "
    "is safe.",
]


# --- Main training routine -----------------------------------------------------


def train(settings: Settings, csv_path: Path, cv_folds: int = 5, verbose: bool = True) -> dict:
    """Run the full pipeline and return the metadata dict."""

    def log(msg: str) -> None:
        if verbose:
            print(msg, flush=True)

    df = load_processed(csv_path, min_per_class=cv_folds * 2)
    pairs = zip(df["subject"], df["body"], strict=True)
    texts = np.array([build_model_text(s, b) for s, b in pairs])
    y = df["label"].to_numpy()

    groups = campaign_groups(df)
    idx_train, idx_test = group_train_test_split(
        y, groups, test_size=settings.test_size, seed=settings.random_seed
    )
    x_train, x_test = texts[idx_train], texts[idx_test]
    y_train, y_test = y[idx_train], y[idx_test]
    log(f"Dataset: {len(df)} emails -> train {len(idx_train)} / test {len(idx_test)}")

    candidates = build_candidates(settings.random_seed)
    cv = StratifiedGroupKFold(n_splits=cv_folds, shuffle=True, random_state=settings.random_seed)
    cv_results: dict[str, dict] = {}
    for name, pipe in candidates.items():
        log(f"Cross-validating {ALGORITHM_LABELS[name]} ({cv_folds} folds)...")
        scores = cross_validate(
            pipe,
            x_train,
            y_train,
            groups=groups[idx_train],
            cv=cv,
            scoring=("f1", "precision", "recall"),
            n_jobs=1,
        )
        cv_results[name] = {
            "f1_mean": float(np.mean(scores["test_f1"])),
            "f1_std": float(np.std(scores["test_f1"])),
            "precision_mean": float(np.mean(scores["test_precision"])),
            "recall_mean": float(np.mean(scores["test_recall"])),
        }
        log(f"  CV F1 = {cv_results[name]['f1_mean']:.4f} ± {cv_results[name]['f1_std']:.4f}")

    best_name = max(cv_results, key=lambda n: cv_results[n]["f1_mean"])
    log(f"Selected by CV: {ALGORITHM_LABELS[best_name]}")

    comparison: dict[str, dict] = {}
    fitted: dict[str, Pipeline] = {}
    for name, pipe in candidates.items():
        pipe.fit(x_train, y_train)
        fitted[name] = pipe
        comparison[name] = compute_metrics(y_test, pipe.predict_proba(x_test)[:, LABEL_PHISHING])

    best = fitted[best_name]
    test_metrics = comparison[best_name]
    log(
        f"Test set: precision {test_metrics['precision_phishing']:.4f}, "
        f"recall {test_metrics['recall_phishing']:.4f}, F1 {test_metrics['f1_phishing']:.4f}, "
        f"ROC-AUC {test_metrics['roc_auc']:.4f}"
    )

    train_df, test_df = df.iloc[idx_train], df.iloc[idx_test]
    now = datetime.now(UTC)
    metadata = {
        "model_version": now.strftime("%Y%m%d-%H%M%S"),
        "created_at": now.isoformat(timespec="seconds"),
        "model_name": best_name,
        "algorithm": ALGORITHM_LABELS[best_name],
        "label_names": {str(k): v for k, v in LABEL_NAMES.items()},
        "environment": {
            "python_version": platform.python_version(),
            "sklearn_version": sklearn.__version__,
        },
        "dataset": {
            "path": str(csv_path.name),
            "sha256": file_sha256(csv_path),
            "n_total": len(df),
            "n_train": len(idx_train),
            "n_test": len(idx_test),
            "by_source": {k: int(v) for k, v in df["source"].value_counts().items()},
            "class_counts": {LABEL_NAMES[k]: int((y == k).sum()) for k in LABEL_NAMES},
            "train_class_counts": {LABEL_NAMES[k]: int((y_train == k).sum()) for k in LABEL_NAMES},
            "test_class_counts": {LABEL_NAMES[k]: int((y_test == k).sum()) for k in LABEL_NAMES},
        },
        "split": {
            "method": (
                "stratified group split (group = normalised subject) after exact-duplicate removal"
            ),
            "test_size": settings.test_size,
            "random_seed": settings.random_seed,
            "test_subject_overlap_rate": subject_overlap_rate(train_df, test_df),
        },
        "selection": {
            "method": (
                f"{cv_folds}-fold stratified group cross-validation F1 on the training set only"
            ),
            "cv_results": cv_results,
        },
        "test_metrics": test_metrics,
        "comparison_test_metrics": comparison,
        "top_features": top_features(best),
        "limitations": LIMITATIONS,
    }

    _atomic_write_bytes_via(settings.model_path, lambda p: joblib.dump(best, p))
    metadata["model_sha256"] = file_sha256(settings.model_path)
    _write_json(settings.model_metadata_path, metadata)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    _write_json(settings.reports_dir / "metrics.json", metadata)
    write_report(settings.reports_dir / "evaluation_report.md", metadata)
    # Held-out test IDs, so the full risk engine can later be evaluated on exactly
    # the same unseen emails (scripts/evaluate_engine.py).
    _write_json(
        settings.reports_dir / TEST_SPLIT_FILE,
        {
            "model_version": metadata["model_version"],
            "dataset_sha256": metadata["dataset"]["sha256"],
            "test_ids": [str(i) for i in test_df["id"]],
        },
    )
    log(f"Saved model to {settings.model_path}")
    log(f"Saved report to {settings.reports_dir / 'evaluation_report.md'}")
    return metadata


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Train the PhishGuard AI email classifier")
    parser.add_argument("--data", type=Path, default=settings.processed_data_dir / PROCESSED_CSV)
    parser.add_argument("--cv-folds", type=int, default=5)
    args = parser.parse_args(argv)
    if not 2 <= args.cv_folds <= 10:
        print("ERROR: --cv-folds must be between 2 and 10", file=sys.stderr)
        return 2
    try:
        train(settings, args.data, cv_folds=args.cv_folds)
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
