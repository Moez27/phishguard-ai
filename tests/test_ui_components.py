"""Tests for chart builders, theme helpers and indicator labels."""

import re
from datetime import date

import pandas as pd

from components.charts import (
    activity_over_time,
    risk_distribution,
    top_indicators,
    verdict_breakdown,
)
from components.theme import defang, verdict_text
from services.signals import SIGNAL_LABELS, signal_label
from tests.conftest import PROJECT_ROOT


def test_defang():
    assert defang("https://login.bank.example/a.php") == "hxxps://login[.]bank[.]example/a[.]php"
    assert defang("HTTP://x.example") == "hxxp://x[.]example"


def test_verdict_text_has_icon_and_label():
    assert verdict_text("phishing") == "✖ Likely phishing"
    assert verdict_text("legitimate").startswith("✔")


def test_verdict_breakdown_labels_and_values():
    fig = verdict_breakdown({"legitimate": 3, "suspect": 1, "phishing": 0})
    bar = fig.data[0]
    assert list(bar.x) == [3, 1, 0]
    assert all(lbl[0] in "✔⚠✖" for lbl in bar.y)  # never colour alone


def test_activity_chart_one_trace_per_verdict():
    df = pd.DataFrame(
        {"day": [date(2026, 11, 1)] * 3, "verdict": ["legitimate", "suspect", "phishing"],
         "count": [1, 2, 3]}
    )  # fmt: skip
    fig = activity_over_time(df)
    assert [t.name for t in fig.data] == [
        "✔ Likely legitimate",
        "⚠ Suspicious",
        "✖ Likely phishing",
    ]
    assert fig.layout.barmode == "stack"
    assert "yaxis2" not in fig.layout  # single y-axis


def test_risk_distribution_marks_thresholds():
    fig = risk_distribution([("phishing", 0.9), ("legitimate", 0.1)], 0.4, 0.7)
    assert len(fig.layout.shapes) == 2
    assert list(fig.data[0].x) == [0.9, 0.1]


def test_empty_charts_do_not_fail():
    verdict_breakdown({})
    risk_distribution([], 0.4, 0.7)
    top_indicators([])


def test_every_indicator_code_has_a_label():
    pattern = re.compile(r'"((?:url|content|email|attachment|sender)_[a-z_]+)"')
    codes = set()
    for path in (PROJECT_ROOT / "services").glob("*_analyzer.py"):
        codes |= set(pattern.findall(path.read_text(encoding="utf-8")))
    assert codes, "no indicator code found"
    missing = codes - set(SIGNAL_LABELS)
    assert not missing, f"codes without a label: {missing}"
    assert signal_label("unknown_code") == "Unknown code"
