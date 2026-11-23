"""Fill the history with the built-in examples, for a demonstration.

Usage::

    python -m scripts.seed_demo                # add the examples to the history
    python -m scripts.seed_demo --reset --yes  # erase the history first, then add them

Every example is analysed by the REAL engine (AI model + rules), exactly as in the
interface; nothing is invented. Records are tagged ``"source": "demo_example"`` in
their metadata so they can always be told apart from real analyses.
"""

from __future__ import annotations

import argparse
import dataclasses
import sys

from config.settings import get_settings
from database.repository import delete_all_analyses
from services.analysis import load_classifier, run_email_analysis, run_url_analysis
from services.examples import EMAIL_EXAMPLES, URL_EXAMPLES
from services.history import record_analysis

DEMO_TAG = {"source": "demo_example"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Add the built-in examples to the history")
    parser.add_argument("--reset", action="store_true", help="erase the history first")
    parser.add_argument("--yes", action="store_true", help="confirm --reset without a prompt")
    args = parser.parse_args(argv)
    settings = get_settings()

    if args.reset:
        if not args.yes:
            answer = input(f"Erase the entire history in {settings.db_path}? [y/N] ")
            if answer.strip().lower() not in {"y", "yes"}:
                print("Cancelled.")
                return 1
        print(f"History erased ({delete_all_analyses(settings.db_path)} analyses deleted).")

    classifier, problem = load_classifier(settings)
    if classifier is None:
        print(f"WARNING: {problem} Emails will be analysed with rules only.", file=sys.stderr)

    print(f"{'Type':<6} {'Verdict':<18} {'Risk':>5}  Example")
    for name, (subject, text) in EMAIL_EXAMPLES.items():
        result = run_email_analysis(text, settings, classifier, subject=subject)
        tagged = dataclasses.replace(result, metadata={**result.metadata, **DEMO_TAG})
        record_analysis(tagged, settings, raw_text=text)
        print(f"{'email':<6} {result.verdict.label:<18} {result.risk_score:>5.0%}  {name}")
    for name, url in URL_EXAMPLES.items():
        result = run_url_analysis(url, settings)
        tagged = dataclasses.replace(result, metadata={**result.metadata, **DEMO_TAG})
        record_analysis(tagged, settings)
        print(f"{'url':<6} {result.verdict.label:<18} {result.risk_score:>5.0%}  {name}")
    print(f"Done. History database: {settings.db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
