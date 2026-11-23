"""Load the trained model and produce predictions and term-level explanations.

Security: ``joblib.load`` unpickles Python objects, which can execute code.
The model is therefore only loaded from the project's own ``models/`` folder,
and its SHA-256 must match the hash recorded in its metadata at training time.
Never load a model file received from an untrusted source.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from ml.dataset import LABEL_NAMES, LABEL_PHISHING
from ml.preprocess import build_model_text

DECISION_THRESHOLD = 0.5


class ModelNotAvailableError(RuntimeError):
    """Raised when no valid trained model can be loaded."""


@dataclass(frozen=True)
class Prediction:
    """Model output for one email."""

    probability: float  # estimated probability of the phishing class, in [0, 1]
    label: int
    label_name: str


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feature_weights(pipeline: Pipeline) -> np.ndarray:
    """Per-term weight towards the phishing class (positive = phishing).

    * Naive Bayes: log P(term | phishing) - log P(term | legitimate)
    * Calibrated linear SVM: average of the SVM coefficients across folds
    """
    clf = pipeline.named_steps["clf"]
    if isinstance(clf, MultinomialNB):
        return clf.feature_log_prob_[1] - clf.feature_log_prob_[0]
    if isinstance(clf, CalibratedClassifierCV):
        coefs = [cc.estimator.coef_[0] for cc in clf.calibrated_classifiers_]
        return np.mean(coefs, axis=0)
    if hasattr(clf, "coef_"):
        return np.asarray(clf.coef_[0])
    raise TypeError(f"Unsupported classifier for explanations: {type(clf).__name__}")


class PhishingClassifier:
    """Thin wrapper around the saved scikit-learn pipeline."""

    def __init__(self, pipeline: Pipeline, metadata: dict) -> None:
        self.pipeline = pipeline
        self.metadata = metadata
        self._vectorizer = pipeline.named_steps["tfidf"]
        self._terms = self._vectorizer.get_feature_names_out()
        self._weights = feature_weights(pipeline)

    @classmethod
    def load(cls, model_path: Path, metadata_path: Path) -> PhishingClassifier:
        if not model_path.is_file() or not metadata_path.is_file():
            raise ModelNotAvailableError(
                "No trained model found. Run: python -m scripts.prepare_data "
                "then python -m ml.train"
            )
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ModelNotAvailableError(f"Model metadata is unreadable: {exc}") from exc
        expected = metadata.get("model_sha256")
        if not expected or file_sha256(model_path) != expected:
            raise ModelNotAvailableError(
                "Model file integrity check failed (hash does not match metadata). "
                "Retrain the model with: python -m ml.train"
            )
        pipeline = joblib.load(model_path)
        return cls(pipeline, metadata)

    @property
    def version(self) -> str:
        return str(self.metadata.get("model_version", "unknown"))

    @property
    def algorithm(self) -> str:
        return str(self.metadata.get("algorithm", "unknown"))

    def predict(self, subject: str, body: str) -> Prediction:
        text = build_model_text(subject, body)
        proba = float(self.pipeline.predict_proba([text])[0][LABEL_PHISHING])
        label = LABEL_PHISHING if proba >= DECISION_THRESHOLD else 1 - LABEL_PHISHING
        return Prediction(probability=proba, label=label, label_name=LABEL_NAMES[label])

    def explain(self, subject: str, body: str, top_n: int = 8) -> list[tuple[str, float]]:
        """Terms of this email that pushed the score towards *phishing* the most.

        Contribution = TF-IDF value of the term in this email x model weight.
        Only terms with a positive contribution are returned.
        """
        text = build_model_text(subject, body)
        row = self._vectorizer.transform([text]).tocoo()
        contributions = [
            (str(self._terms[j]), float(v * self._weights[j]))
            for j, v in zip(row.col, row.data, strict=True)
        ]
        positive = [c for c in contributions if c[1] > 0]
        positive.sort(key=lambda c: c[1], reverse=True)
        return positive[:top_n]
