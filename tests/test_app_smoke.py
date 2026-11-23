"""UI tests: the real Streamlit pages, driven with AppTest in an isolated folder."""

import pytest
from streamlit.testing.v1 import AppTest

from config.settings import load_settings
from database.repository import get_stats
from tests.conftest import PROJECT_ROOT

APP = str(PROJECT_ROOT / "app.py")


@pytest.fixture
def isolated(clean_env, tmp_path):
    """Empty data/model folders: no history, no model (rules-only mode)."""
    clean_env.setenv("PHISHGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_env.setenv("PHISHGUARD_MODELS_DIR", str(tmp_path / "models"))
    return load_settings()


def _app(page: str | None = None) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    if page:
        at.switch_page(page)
        at.run()
    assert not at.exception, at.exception
    return at


def _markdown(at: AppTest) -> str:
    return " ".join(m.value for m in at.markdown)


def test_dashboard_empty_state(isolated):
    at = _app()
    assert any("No analysis has been recorded yet" in i.value for i in at.info)
    assert "Platform status" in _markdown(at)
    assert not isolated.db_path.exists()  # viewing the dashboard creates nothing


def test_email_analysis_flow_and_dashboard(isolated):
    at = _app("pages/email_analysis.py")
    assert any("not available" in w.value for w in at.warning)  # no model -> rules only
    at.text_area(key="email_text").input(
        "Dear customer, your account will be suspended. Verify your password immediately at "
        "http://203.0.113.9/login"
    )
    at.button[0].click()
    at.run()
    assert not at.exception
    md = _markdown(at)
    assert "Likely phishing" in md
    assert "Request for credentials" in md
    assert "saved to history as ID" in " ".join(c.value for c in at.caption)

    stats = get_stats(isolated.db_path)
    assert stats.total == 1 and stats.by_verdict["phishing"] == 1

    dash = _app()
    assert not dash.info  # no empty state any more
    assert "Total analyses" in _markdown(dash)
    assert len(dash.dataframe) == 1  # latest analyses table


def test_email_empty_input_shows_error(isolated):
    at = _app("pages/email_analysis.py")
    at.button[0].click()
    at.run()
    assert any("paste" in e.value.lower() for e in at.error)
    assert not isolated.db_path.exists()


def test_url_analysis_defangs_and_records(isolated):
    at = _app("pages/url_analysis.py")
    at.text_input(key="url_input").input("http://paypal.com.secure-login.verify-account.xyz/x")
    at.button[0].click()
    at.run()
    assert not at.exception
    md = _markdown(at)
    assert "hxxp://paypal[.]com[.]secure-login[.]verify-account[.]xyz/x" in md
    assert "Likely phishing" in md
    assert get_stats(isolated.db_path).by_type["url"] == 1


def test_url_invalid_scheme_error(isolated):
    at = _app("pages/url_analysis.py")
    at.text_input(key="url_input").input("javascript:alert(1)")
    at.button[0].click()
    at.run()
    assert any("Unsupported URL scheme" in e.value for e in at.error)


def test_history_empty_state(isolated):
    at = _app("pages/history.py")
    assert any("history is empty" in i.value for i in at.info)


def test_history_filters_and_exports(isolated):
    from datetime import UTC, datetime

    from database.repository import insert_analysis

    for verdict, kind, target in [
        ("phishing", "url", "203.0.113.7"),
        ("legitimate", "email", "colleague.example"),
    ]:
        insert_analysis(
            isolated.db_path, analysis_type=kind, verdict=verdict, risk_score=0.5,
            rule_score=0.5, ml_probability=None, model_version=None, target=target,
            signal_codes=[], metadata={}, duration_ms=1.0, created_at=datetime.now(UTC),
        )  # fmt: skip
    at = _app("pages/history.py")
    assert "**2** matching analyses" in _markdown(at)
    assert len(at.dataframe) == 1

    at.multiselect(key="history_verdicts").select("phishing")
    at.run()
    assert not at.exception
    assert "**1** matching analysis" in _markdown(at)

    at.text_input(key="history_search").input("nothing-matches-this")
    at.run()
    assert any("No analysis matches" in i.value for i in at.info)


def test_about_page(isolated):
    at = _app("pages/about.py")
    md = _markdown(at)
    assert "Security and privacy" in md
    assert "CC BY 4.0" in md
    assert "AI model: not trained" in " ".join(c.value for c in at.caption)


def test_seed_demo_script(isolated):
    from database.repository import get_stats, recent_analyses
    from scripts.seed_demo import main as seed_main

    assert seed_main([]) == 0
    stats = get_stats(isolated.db_path)
    assert stats.total == 8 and stats.by_type == {"email": 4, "url": 4}
    assert all(
        r.metadata.get("source") == "demo_example" for r in recent_analyses(isolated.db_path)
    )
    assert seed_main(["--reset", "--yes"]) == 0
    assert get_stats(isolated.db_path).total == 8  # reset, then re-seeded
