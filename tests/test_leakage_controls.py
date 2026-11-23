"""Tests for the anti-leakage controls: artifact scrubbing and group-aware splitting."""

import numpy as np
import pandas as pd

from ml.dataset import scrub_corpus_artifacts
from ml.train import campaign_groups, group_train_test_split


def test_scrub_removes_collector_identity():
    text = scrub_corpus_artifacts("Dear jose@monkey.org, your monkey.org mailbox is full. Jose")
    lowered = text.lower()
    assert "jose" not in lowered and "monkey" not in lowered
    assert "mailbox is full" in text


def test_scrub_removes_mailman_footer():
    body = (
        "Real content here.\n"
        "_______________________________________________\n"
        "Razor-users mailing list\nRazor-users@lists.sourceforge.net\n"
        "https://lists.sourceforge.net/lists/listinfo/razor-users\n"
    )
    assert scrub_corpus_artifacts(body).strip() == "Real content here."


def test_scrub_keeps_plain_underscore_separator():
    body = "Part one\n____________________\nPart two continues the message."
    assert "Part two" in scrub_corpus_artifacts(body)


def test_scrub_removes_sponsor_footer_and_feed_lines():
    body = (
        "URL: http://boingboing.net/85534\nDate: Not supplied\n\nA story about robots.\n"
        "-------------------------------------------------------\n"
        "This sf.net email is sponsored by: ThinkGeek\nWelcome to geek heaven.\n"
    )
    out = scrub_corpus_artifacts(body)
    assert "A story about robots." in out
    assert "URL:" not in out and "Date:" not in out
    assert "sponsored" not in out


def test_group_split_keeps_campaigns_together():
    subjects = [f"campaign {i % 30}" for i in range(300)] + [""] * 50
    labels = [i % 2 for i in range(300)] + [0] * 50
    df = pd.DataFrame({"id": [f"id{i}" for i in range(350)], "subject": subjects, "label": labels})
    groups = campaign_groups(df)
    tr, te = group_train_test_split(np.array(labels), groups, test_size=0.2, seed=42)
    assert set(groups[tr]).isdisjoint(groups[te])
    assert len(set(tr) | set(te)) == 350
    # empty subjects are separate groups, not one giant group
    assert len({g for g in groups if g.startswith("id:")}) == 50
