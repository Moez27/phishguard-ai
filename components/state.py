"""Cached resources shared by pages (settings, trained model)."""

from __future__ import annotations

import streamlit as st

from config.settings import Settings, get_settings
from ml.predict import PhishingClassifier
from services.analysis import load_classifier


@st.cache_resource(show_spinner="Loading the AI model…")
def _cached_classifier(
    _settings: Settings, model_mtime: float
) -> tuple[PhishingClassifier | None, str | None]:
    # model_mtime is part of the cache key: retraining reloads the model automatically.
    return load_classifier(_settings)


def classifier() -> tuple[PhishingClassifier | None, str | None]:
    settings = get_settings()
    path = settings.model_path
    mtime = path.stat().st_mtime if path.is_file() else 0.0
    return _cached_classifier(settings, mtime)
