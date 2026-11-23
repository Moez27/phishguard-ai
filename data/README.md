# Datasets

PhishGuard AI is trained on the two public corpora named in the project specification
(Projet 7, *Cybersecurity Projects*). **They are not included in this repository**: you
download them yourself, and `data/raw/` and `data/processed/` are git-ignored.

> ⚠️ These corpora contain real (old) phishing messages. Treat them as hostile content:
> do not open links found inside them and do not execute anything they contain.
> The preparation pipeline only reads them as text.

## 1. Sources

| Corpus | Role in PhishGuard | Where to get it |
|---|---|---|
| **SpamAssassin Public Corpus** | `easy_ham` + `hard_ham` → **legitimate** class | <https://spamassassin.apache.org/old/publiccorpus/> |
| **Nazario Phishing Corpus** | all messages → **phishing** class | <https://monkey.org/~jose/phishing/> |

**Licences.** The Nazario Phishing Corpus is published under **Creative Commons Attribution 4.0
(CC BY 4.0)** (see `LICENSE.txt` on the site), so it must be credited to Jose Nazario in the
report and the presentation. The SpamAssassin Public Corpus is distributed by the Apache
SpamAssassin project for research and testing; cite it as the source. Neither corpus is
redistributed in this repository.

**Recommended subset (≈ 84 MB in total):**

| File | Size | Why |
|---|---|---|
| `20030228_easy_ham.tar.bz2`, `20030228_easy_ham_2.tar.bz2`, `20030228_hard_ham.tar.bz2` | 3.7 MB | all available legitimate mail |
| `phishing0.mbox` … `phishing3.mbox` | 37.8 MB | phishing from roughly the same period as the ham (reduces date bias) |
| `phishing-2023`, `phishing-2024`, `phishing-2025` | 42.0 MB | recent phishing, closer to what the demo will show |

`private-phishing4.mbox` and `20051114.mbox` are left out. The first has an unclear status,
and the second probably overlaps with the files above.

> **Antivirus note.** On the development machine, the antivirus blocked `phishing0.mbox`,
> `phishing1.mbox` and `phishing-2023` while they were being written. This is expected, since
> they contain real phishing samples. The current model was trained **without** these three files:
> it uses `phishing2.mbox`, `phishing3.mbox`, `phishing-2024`, `phishing-2025` and all three
> SpamAssassin ham archives. Do not turn the antivirus off to get them. If you want them, ask your
> system administrator about an exclusion limited to `data/raw/nazario/`.

**SpamAssassin `spam` folders** contain generic spam (ads, scams), **not phishing**. By default
they are **ignored** by the loader so the model learns "phishing vs legitimate" rather than
"spam vs ham".

## 2. Expected layout

After downloading and extracting the files, arrange them like this:

```
data/raw/
├── spamassassin/
│   ├── easy_ham/        # from 20030228_easy_ham.tar.bz2 (and/or easy_ham_2)
│   ├── hard_ham/        # from 20030228_hard_ham.tar.bz2
│   └── spam/            # optional, excluded by default
└── nazario/
    ├── phishing0.mbox
    ├── phishing1.mbox
    └── ...              # any of the yearly phishing-YYYY files, kept in mbox format
```

- SpamAssassin: one raw RFC 822 email per file. The archives also contain a `cmds` file, which is ignored.
- Nazario: mbox files, which hold many emails in one file, each starting with a `From ` line.

To extract `.tar.bz2` archives on Windows, run `tar -xjf <archive>.tar.bz2` in PowerShell (`tar` is built into Windows 10+),
or use 7-Zip.

## 3. Processed format

`python -m scripts.prepare_data` produces `data/processed/emails.csv` and
`data/processed/dataset_stats.json`, which records counts per source, skipped messages and duplicates removed:

| Column | Type | Description |
|---|---|---|
| `id` | str | Stable hash of the normalised text (used for deduplication) |
| `source` | str | `spamassassin_easy_ham`, `spamassassin_hard_ham`, `nazario` |
| `subject` | str | Decoded subject line |
| `body` | str | Plain text body (HTML converted to text with BeautifulSoup) |
| `label` | int | `0` = legitimate, `1` = phishing |

## 4. Leakage and bias controls (implemented)

These controls are implemented in `ml/dataset.py` and `ml/train.py`:

- **Headers are discarded.** Only the subject and body are used. Otherwise the model would learn
  *which corpus or mail server a message came from* (Received headers, dates, mailing list
  footers) instead of phishing content.
- **Collection artifacts are removed from both classes in the same way** (`scrub_corpus_artifacts`):
  - the Nazario collector's address, domain and name (`jose@monkey.org`, which phishing kits insert into
    the message, as in "Dear jose@monkey.org");
  - Mailman mailing-list footers and SourceForge sponsor footers;
  - `URL:` / `Date:` lines added by the RSS-to-email gateway.

  On the first training run, without this step, these were among the model's strongest features
  (`monkey`, `mailing list`, `url urltoken`).
- **Duplicates are removed before the train/test split.** This stops the same message from
  appearing in both sets.
- **The split is grouped by campaign** (`StratifiedGroupKFold`): all emails with the same
  normalised subject stay on the same side of the train/test split and of each cross-validation fold.
  Without grouping, 40.7% of test emails shared a subject with a training email. With grouping, 0% do.
- **The split is seeded** (`PHISHGUARD_RANDOM_SEED`), so it is reproducible.
- **TF-IDF is fitted on the training set only**, inside a scikit-learn `Pipeline`.

### Known limits

- **Modern legitimate emails get high phishing probabilities.** The legitimate class is
  2002-era tech mailing-list mail, so phrases such as "your account", "customer" and
  "online banking" appear almost only in phishing. In a manual sanity check, a genuine-looking
  "your order has shipped" email scored 0.95 and a bank statement notice scored 0.99. For this reason
  PhishGuard never uses the ML probability alone: it is combined with explainable rules
  (URL analysis, credential requests, urgency) in the risk engine.
- Recent Nazario samples contain filler text pasted in to fool spam filters (excerpts from novels), so words such as
  `she`, `he` and character names lean slightly towards phishing.

- The corpora come from different sources and periods: SpamAssassin is from around 2002–2005, and Nazario spans
  2005 to recent years. The model can partly learn these differences in style and time.
- Phishing techniques change. Scores on these test sets **do not prove** real-world detection
  performance on today's emails.
