"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings as settings_module  # noqa: E402


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove every PHISHGUARD_* variable and ignore any local .env file."""
    import os

    for key in list(os.environ):
        if key.startswith(settings_module.ENV_PREFIX):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(settings_module, "load_dotenv", lambda *a, **k: False)
    settings_module.get_settings.cache_clear()
    yield monkeypatch
    settings_module.get_settings.cache_clear()


@pytest.fixture
def tmp_settings(clean_env: pytest.MonkeyPatch, tmp_path: Path) -> settings_module.Settings:
    """Settings whose data/model directories point to an empty temp folder."""
    clean_env.setenv("PHISHGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_env.setenv("PHISHGUARD_MODELS_DIR", str(tmp_path / "models"))
    return settings_module.load_settings()
