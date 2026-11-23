"""Load the evaluation results produced by the training/evaluation scripts.

Nothing here computes or invents metrics: it only reads the JSON files written by
``ml/train.py`` (model) and ``scripts/evaluate_engine.py`` (full engine).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from config.settings import Settings
from services.system_status import read_model_metadata

ENGINE_METRICS_FILE = "engine_metrics.json"


@dataclass(frozen=True)
class EvaluationData:
    model: dict | None  # models/model_metadata.json
    engine: dict | None  # reports/engine_metrics.json (None if absent or stale)
    engine_stale: bool  # engine file exists but belongs to another model version


def load_evaluation(settings: Settings) -> EvaluationData:
    model = read_model_metadata(settings)
    engine_path = settings.reports_dir / ENGINE_METRICS_FILE
    engine = None
    stale = False
    if model and engine_path.is_file():
        try:
            data = json.loads(engine_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None
        if data is not None:
            if data.get("model_version") == model.get("model_version"):
                engine = data
            else:
                stale = True
    return EvaluationData(model=model, engine=engine, engine_stale=stale)
