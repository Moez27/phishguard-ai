"""Centralized configuration for PhishGuard AI.

All tunable values live here. Each one can be overridden with an environment
variable (or a local ``.env`` file, never committed) prefixed with ``PHISHGUARD_``.

Usage::

    from config.settings import get_settings
    settings = get_settings()
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR: Path = Path(__file__).resolve().parent.parent

ENV_PREFIX = "PHISHGUARD_"


class SettingsError(ValueError):
    """Raised when a configuration value is missing or invalid."""


def _env(name: str, default: str) -> str:
    return os.getenv(f"{ENV_PREFIX}{name}", default)


def _env_int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise SettingsError(f"{ENV_PREFIX}{name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = _env(name, str(default))
    try:
        return float(raw)
    except ValueError as exc:
        raise SettingsError(f"{ENV_PREFIX}{name} must be a number, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise SettingsError(f"{ENV_PREFIX}{name} must be a boolean, got {raw!r}")


def _env_path(name: str, default: Path) -> Path:
    raw = os.getenv(f"{ENV_PREFIX}{name}")
    if not raw:
        return default
    path = Path(raw)
    return path if path.is_absolute() else BASE_DIR / path


@dataclass(frozen=True)
class Settings:
    """Immutable application settings."""

    # --- Paths ---
    base_dir: Path
    data_dir: Path
    raw_data_dir: Path
    processed_data_dir: Path
    models_dir: Path
    reports_dir: Path
    db_path: Path
    model_path: Path
    model_metadata_path: Path

    # --- Input validation limits ---
    max_email_chars: int
    max_upload_bytes: int
    max_url_length: int
    allowed_upload_extensions: tuple[str, ...]

    # --- Risk scoring thresholds (risk score in [0, 1]) ---
    suspect_threshold: float
    phishing_threshold: float
    # Share of the ML probability in the email risk score (the rest comes from rules)
    ml_weight: float

    # --- Machine learning ---
    random_seed: int
    test_size: float

    # --- Privacy ---
    store_email_body: bool

    # --- Logging ---
    log_level: str

    def validate(self) -> None:
        """Check value ranges. Raises :class:`SettingsError` on invalid config."""
        if not 0.0 < self.suspect_threshold < self.phishing_threshold < 1.0:
            raise SettingsError(
                "Thresholds must satisfy 0 < suspect_threshold < phishing_threshold < 1 "
                f"(got {self.suspect_threshold} and {self.phishing_threshold})"
            )
        if not 0.0 <= self.ml_weight <= 1.0:
            raise SettingsError(f"ml_weight must be between 0 and 1, got {self.ml_weight}")
        if not 0.05 <= self.test_size <= 0.5:
            raise SettingsError(f"test_size must be between 0.05 and 0.5, got {self.test_size}")
        for name in ("max_email_chars", "max_upload_bytes", "max_url_length"):
            if getattr(self, name) <= 0:
                raise SettingsError(f"{name} must be positive")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise SettingsError(f"Invalid log level: {self.log_level}")


def load_settings() -> Settings:
    """Build settings from defaults + environment variables, then validate them."""
    load_dotenv(BASE_DIR / ".env", override=False)

    data_dir = _env_path("DATA_DIR", BASE_DIR / "data")
    models_dir = _env_path("MODELS_DIR", BASE_DIR / "models")

    settings = Settings(
        base_dir=BASE_DIR,
        data_dir=data_dir,
        raw_data_dir=data_dir / "raw",
        processed_data_dir=data_dir / "processed",
        models_dir=models_dir,
        reports_dir=_env_path("REPORTS_DIR", BASE_DIR / "reports"),
        db_path=_env_path("DB_PATH", data_dir / "phishguard.db"),
        model_path=models_dir / "phishing_model.joblib",
        model_metadata_path=models_dir / "model_metadata.json",
        max_email_chars=_env_int("MAX_EMAIL_CHARS", 100_000),
        max_upload_bytes=_env_int("MAX_UPLOAD_BYTES", 200 * 1024),
        max_url_length=_env_int("MAX_URL_LENGTH", 2048),
        allowed_upload_extensions=(".txt",),
        suspect_threshold=_env_float("SUSPECT_THRESHOLD", 0.40),
        phishing_threshold=_env_float("PHISHING_THRESHOLD", 0.70),
        ml_weight=_env_float("ML_WEIGHT", 0.50),
        random_seed=_env_int("RANDOM_SEED", 42),
        test_size=_env_float("TEST_SIZE", 0.20),
        store_email_body=_env_bool("STORE_EMAIL_BODY", False),
        log_level=_env("LOG_LEVEL", "INFO").upper(),
    )
    settings.validate()
    return settings


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings."""
    return load_settings()
