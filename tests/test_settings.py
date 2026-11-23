"""Tests for centralized configuration."""

import pytest

from config.settings import BASE_DIR, SettingsError, load_settings


def test_defaults_load_and_are_valid(clean_env):
    s = load_settings()
    assert s.base_dir == BASE_DIR
    assert s.suspect_threshold < s.phishing_threshold
    assert s.store_email_body is False  # privacy by default
    assert s.allowed_upload_extensions == (".txt",)
    assert s.db_path.parent == s.data_dir


def test_env_override(clean_env):
    clean_env.setenv("PHISHGUARD_MAX_URL_LENGTH", "500")
    clean_env.setenv("PHISHGUARD_STORE_EMAIL_BODY", "yes")
    clean_env.setenv("PHISHGUARD_LOG_LEVEL", "debug")
    s = load_settings()
    assert s.max_url_length == 500
    assert s.store_email_body is True
    assert s.log_level == "DEBUG"


def test_relative_path_resolved_from_project_root(clean_env):
    clean_env.setenv("PHISHGUARD_DATA_DIR", "custom_data")
    s = load_settings()
    assert s.data_dir == BASE_DIR / "custom_data"
    assert s.raw_data_dir == BASE_DIR / "custom_data" / "raw"


@pytest.mark.parametrize(
    ("suspect", "phishing"),
    [("0.8", "0.6"), ("0", "0.5"), ("0.4", "1.0"), ("0.5", "0.5")],
)
def test_invalid_thresholds_rejected(clean_env, suspect, phishing):
    clean_env.setenv("PHISHGUARD_SUSPECT_THRESHOLD", suspect)
    clean_env.setenv("PHISHGUARD_PHISHING_THRESHOLD", phishing)
    with pytest.raises(SettingsError):
        load_settings()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MAX_EMAIL_CHARS", "abc"),
        ("MAX_EMAIL_CHARS", "0"),
        ("TEST_SIZE", "0.9"),
        ("ML_WEIGHT", "1.5"),
        ("STORE_EMAIL_BODY", "maybe"),
        ("LOG_LEVEL", "VERBOSE"),
    ],
)
def test_invalid_values_rejected(clean_env, name, value):
    clean_env.setenv(f"PHISHGUARD_{name}", value)
    with pytest.raises(SettingsError):
        load_settings()
