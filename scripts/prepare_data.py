"""Prepare the training dataset from the raw corpora.

Usage::

    python -m scripts.prepare_data

Reads   data/raw/spamassassin/{easy_ham*,hard_ham*}/  and  data/raw/nazario/*  (mbox)
Writes  data/processed/emails.csv  and  data/processed/dataset_stats.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from config.settings import get_settings
from ml.dataset import DatasetError, build_dataset

PROCESSED_CSV = "emails.csv"
STATS_JSON = "dataset_stats.json"


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Build data/processed/emails.csv")
    parser.add_argument("--raw-dir", type=Path, default=settings.raw_data_dir)
    parser.add_argument("--out-dir", type=Path, default=settings.processed_data_dir)
    args = parser.parse_args(argv)

    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(message)s")

    try:
        df, stats = build_dataset(args.raw_dir)
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if df.empty:
        print("ERROR: no usable messages found in the raw folders.", file=sys.stderr)
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.out_dir / PROCESSED_CSV
    df.to_csv(csv_path, index=False, encoding="utf-8")
    (args.out_dir / STATS_JSON).write_text(json.dumps(stats.to_dict(), indent=2), encoding="utf-8")

    print("Raw messages by source:")
    for source, count in sorted(stats.raw_by_source.items()):
        print(f"  {source:<28} {count:>6}")
    print(f"Skipped (unreadable):          {stats.skipped_unreadable:>6}")
    print(f"Skipped (empty after parsing): {stats.skipped_empty:>6}")
    print(f"Duplicates removed:            {stats.duplicates_removed:>6}")
    print("Final dataset:")
    for name, count in stats.final_by_label.items():
        print(f"  {name:<28} {count:>6}")
    print(f"Written: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
