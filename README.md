# 🛡️ PhishGuard AI

**PhishGuard AI** is a platform for detecting and analysing phishing emails and URLs. It is
an engineering project in defensive cybersecurity, Projet 7: *Détection des emails de phishing par IA*.

It analyses emails and URLs submitted by an analyst and estimates their phishing risk by
combining a supervised machine-learning model (TF-IDF + Naive Bayes / SVM) with
explainable rules.

> PhishGuard AI is a **decision-support tool**. A low risk score never guarantees that a
> message or link is safe.

## Documentation

| Document | Contents |
|---|---|
| [docs/PROJECT_REPORT.md](docs/PROJECT_REPORT.md) | Project report: choices, data, results, security, requirements traceability (F01–F09, CA1–CA8, L1–L8), limitations |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layers, analysis flow, training pipeline, stored data (with diagrams) |
| [docs/DEMO.md](docs/DEMO.md) | Step-by-step demonstration scenario, expected results, Q&A preparation |
| [data/README.md](data/README.md) | Dataset sources, licences, layout and leakage controls |
| [reports/evaluation_report.md](reports/evaluation_report.md) | Evaluation of the AI model on the held-out test set |
| [reports/engine_evaluation.md](reports/engine_evaluation.md) | Evaluation of the complete engine (AI + rules) |
| [reports/test_results.txt](reports/test_results.txt) | Test and coverage results |
| [notebooks/exploration.ipynb](notebooks/exploration.ipynb) | Exploratory data analysis (Jupyter) |

## Security measures

| Threat | Protection | Where |
|---|---|---|
| Visiting a malicious link | URLs are parsed as text only: never opened, resolved (no DNS) or sent to a third party; displayed defanged (`hxxp://x[.]example`). A test blocks all network access and runs the analysis. | `services/url_analyzer.py` |
| Malicious attachments | Only the declared file name is read; the content is never decoded, saved or executed. Only `.txt` uploads are accepted. | `ml/preprocess.py`, `services/validation.py` |
| Oversized / binary input | Size limits (email 100,000 characters, upload 200 KB, URL 2,048 characters) and binary detection. | `services/validation.py` |
| Regex denial-of-service (ReDoS) | Bounded patterns. A crafted 50,000-character email used to take about 14 s and now takes about 0.2 s; regression tests check this. | `ml/preprocess.py`, `tests/test_security.py` |
| SQL injection | All queries are parameterised; search wildcards are escaped. | `database/repository.py` |
| HTML / Markdown injection in the UI | Every dynamic value inserted into HTML is escaped; user text echoed in error messages is sanitised. | `components/`, `services/validation.py` |
| CSV / formula injection | Exported cells starting with `= + - @` are neutralised. | `services/reports.py` |
| Tampered model file (pickle code execution) | The SHA-256 of the model is checked against its metadata before loading. | `ml/predict.py` |
| Exposure on the network | The server listens on `localhost` only (Streamlit's default is every interface). XSRF protection is kept on. | `.streamlit/config.toml` |
| Privacy | The history stores minimal metadata, never the email text (unless explicitly enabled); logs contain no email content; Streamlit usage statistics are disabled. | `services/history.py` |
| Secrets | None are needed. Any future key goes in the git-ignored `.env`, never in code. | `.env.example` |

To show the app to another device on a **trusted** network, start it with
`streamlit run app.py --server.address 0.0.0.0`.

## Project status

| Phase | Content | Status |
|---|---|---|
| 1 | Project structure, dependencies, configuration, README | ✅ Done |
| 2 | Dataset preparation and baseline ML pipeline | ✅ Done |
| 3 | Email and URL analysis modules | ✅ Done |
| 4 | Streamlit interface and dashboard | ✅ Done |
| 5 | SQLite history, filtering, CSV export | ✅ Done |
| 6 | Model evaluation page, tests, security hardening | ✅ Done |
| 7 | UI polish, documentation, demo preparation | ✅ Done |

## Requirements

- Windows, macOS or Linux. **No virtual machine is needed.**
- **Python 3.12** is recommended (3.11 also works).
- About 500 MB of disk space for the dependencies and datasets.

## Installation (Windows / PowerShell)

```powershell
# 1. Create and activate a virtual environment (venv, not a VM)
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies (runtime + dev tools)
python -m pip install --upgrade pip
pip install -r requirements-dev.txt

# 3. (Optional) Local configuration
Copy-Item .env.example .env
```

To install the exact versions the project was tested with, use
`pip install -r requirements-lock.txt` instead (verified on Python 3.12.10, Windows 10).

If PowerShell blocks `Activate.ps1`, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call the venv's Python
directly with `.\.venv\Scripts\python.exe`.

On macOS or Linux: `python3.12 -m venv .venv && source .venv/bin/activate`.

## Run the application

```powershell
streamlit run app.py
```

The app opens at <http://localhost:8501>. It has six pages:

| Page | What it does |
|---|---|
| **Dashboard** | Totals, verdict breakdown, 30-day activity, risk-score distribution, most frequent indicators, latest analyses and platform status. Every number is computed from the SQLite history (`data/phishguard.db`); with no analyses yet, the page says so instead of showing placeholder figures. |
| **Email analysis** | Paste text, HTML or a raw email with headers, or upload a `.txt` file. Shows the verdict, risk meter, AI probability, rule score, the indicators found with their severity, the words that raised the AI score, and recommendations. |
| **URL analysis** | Offline analysis of an address. The analysed URL is displayed defanged (`hxxp://example[.]com`) so nobody can click it by mistake. |
| **History** | Search by domain, ID or indicator; filter by verdict, type and date range (UTC); select rows to see details or delete them (with confirmation); erase the whole history from the "Danger zone"; export the filtered results or the statistics to CSV. |
| **Model evaluation** | The real test-set metrics: precision, recall, F1, ROC-AUC, the confusion matrix and the ROC curve. It also shows the model comparison, the complete-engine evaluation, the dataset and split method, the most influential terms and the known limitations. Every figure is read from the files produced by training. |
| **About** | Purpose, how an analysis works, security and privacy, data credits and limitations. |

**CSV exports.** There are three reports:

- **History:** the analyses that match the current filters.
- **Statistics:** totals, the share of each verdict and the most frequent indicators.
- **Single result:** the "Download this result" button on the Email and URL analysis pages.

Files are UTF-8 with a BOM, so Excel shows accents correctly. Any cell that starts with `=`, `+`,
`-` or `@` is prefixed with an apostrophe, so a malicious value such as a crafted domain can't run
as a spreadsheet formula (CSV injection, as recommended by OWASP).

Both analysis pages include **built-in synthetic examples**. Their domains use the reserved
`.example` TLD and the `203.0.113.0/24` documentation range, so they never point to a real site.
Each analysis is saved automatically to the local history with minimal data: date, type, verdict,
scores, indicator codes, and the URL host or sender domain. The email text is not stored unless
`PHISHGUARD_STORE_EMAIL_BODY=true`.

**For a demonstration**, fill the history with the built-in examples. Each one is analysed by the
real engine and tagged `"source": "demo_example"`:

```powershell
python -m scripts.seed_demo                # add the 8 examples
python -m scripts.seed_demo --reset --yes  # erase the history first
```

See [docs/DEMO.md](docs/DEMO.md) for the full scenario.

**Exploration notebook:**

```powershell
jupyter notebook notebooks/exploration.ipynb
```

## Datasets

See [data/README.md](data/README.md) for the sources (SpamAssassin Public Corpus, Nazario
Phishing Corpus), the expected folder layout and the leakage controls.

## Training the model

First place the corpora in `data/raw/` as described in [data/README.md](data/README.md). Then run:

```powershell
python -m scripts.prepare_data   # parse, clean, deduplicate -> data/processed/emails.csv
python -m ml.train               # compare models, evaluate, save model + report
python -m scripts.evaluate_engine  # evaluate the complete engine (AI + rules)
```

What the training does:

1. Splits the deduplicated data into **train/test sets** (80/20, fixed seed). The split is stratified and grouped by subject, so the same campaign is never on both sides.
2. Compares **TF-IDF + Naive Bayes** and **TF-IDF + calibrated linear SVM** with 5-fold
   cross-validation **on the training set only**, and keeps the one with the best F1-score.
3. Evaluates the selected model **once** on the held-out test set.
4. Writes `models/phishing_model.joblib`, `models/model_metadata.json`, `reports/metrics.json`
   and `reports/evaluation_report.md`.

When the model loads, its SHA-256 hash is checked against the hash saved in its metadata. Never load a
model file that comes from an untrusted source: model files are pickles, and loading one can execute code.

`scripts/evaluate_engine.py` evaluates the complete risk engine, which is what the application
actually shows. It runs on exactly the same held-out test emails and writes
`reports/engine_metrics.json` and `reports/engine_evaluation.md`.

**Results with the current model (1,506 unseen test emails):**

| Decision | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| AI model alone (≥ 0.5) | 0.990 | 0.987 | 0.988 | 0.9% |
| Engine: Suspicious or Likely phishing | 0.972 | 0.972 | 0.972 | 2.3% |
| Engine: Likely phishing only | 1.000 | 0.579 | 0.733 | 0.0% |

On these 2002–2025 corpora the AI alone scores higher. The engine's caution, which needs concrete
indicators before it says "Likely phishing", is designed for modern legitimate emails that the
corpora don't contain. The **Model evaluation** page shows all of these numbers and explains them.

## How the risk score works

Each analysis returns a **risk score from 0 to 1**, a **verdict**, the **indicators** found,
and **recommendations**:

| Score | Verdict |
|---|---|
| < 0.40 | ✔ Likely legitimate |
| 0.40 – 0.70 | ⚠ Suspicious |
| ≥ 0.70 | ✖ Likely phishing |

The verdict icons are text symbols, so a verdict never relies on colour alone.

**URL analysis** ([services/url_analyzer.py](services/url_analyzer.py)) is fully offline. The
address is parsed as text and is never opened, resolved or sent to a reputation service. The
indicators it looks for:

- an IP address instead of a domain name;
- `@` in the address;
- a look-alike domain using punycode or non-Latin characters;
- a brand name on an unrelated domain;
- a URL shortener;
- sensitive keywords in the address;
- a top-level domain that is often abused;
- no HTTPS;
- a long address, many subdomains or many hyphens;
- a non-standard port;
- an embedded redirection;
- a link to an executable file.

**Email analysis** ([services/email_analyzer.py](services/email_analyzer.py)) accepts a raw email
with headers, plain text or HTML, in English or French. The indicators it looks for:

- requests for credentials or personal data;
- urgent wording;
- threats of account suspension;
- money or prize lures;
- generic greetings;
- suspicious links, analysed with the URL rules above;
- link text that shows a different domain from the real target;
- dangerous attachment types, identified by file name only and never opened;
- a sender display name that impersonates a brand;
- a Reply-To on a different domain from the sender.

**Combining the evidence** ([services/risk_engine.py](services/risk_engine.py)):

- Rule indicators are combined with a noisy-OR: `rules = 1 − ∏(1 − weightᵢ)`.
- The rule weights are hand-set heuristics, listed in [services/indicators.py](services/indicators.py). They are not learned from data.
- **Email score** = `max(w × p_ML + (1 − w) × rules, 0.9 × rules)`, with `w = PHISHGUARD_ML_WEIGHT` (0.5 by default).

As a result, **the AI model alone can raise an email to "Suspicious" at most**. Reaching "Likely
phishing" needs concrete indicators as well. This compensates for the model's known false
positives on modern legitimate emails (see [data/README.md](data/README.md)). Strong indicators
alone can still reach "Likely phishing". If the model is unavailable, the result uses the rules
only and says so.

## Configuration

All settings are in [config/settings.py](config/settings.py). You can override any of them with
`PHISHGUARD_*` environment variables or in a `.env` file; see [.env.example](.env.example).

| Variable | Default | Meaning |
|---|---|---|
| `PHISHGUARD_SUSPECT_THRESHOLD` | `0.40` | Risk score from which a result is *Suspect* |
| `PHISHGUARD_PHISHING_THRESHOLD` | `0.70` | Risk score from which a result is *Phishing* |
| `PHISHGUARD_ML_WEIGHT` | `0.50` | Share of the ML probability in the email risk score |
| `PHISHGUARD_MAX_EMAIL_CHARS` | `100000` | Maximum email length accepted |
| `PHISHGUARD_MAX_URL_LENGTH` | `2048` | Maximum URL length accepted |
| `PHISHGUARD_STORE_EMAIL_BODY` | `false` | Whether the full email body is kept in the history |

## Tests and code quality

```powershell
pytest
ruff check .
pytest --cov=config --cov=ml --cov=services --cov=database --cov=components --cov=scripts --cov=pages
```

The suite has 208 tests at 94% line coverage. It covers:

- parsing and leakage controls;
- training and prediction, using a synthetic corpus;
- URL and email indicators;
- validation, the risk engine and the history database;
- CSV safety and security regressions;
- the real Streamlit pages, driven with `AppTest`.

The History page's row selection and deletion dialogs were tested manually, because `AppTest`
can't tick rows in a data grid.

## Project structure

```
app.py                 Streamlit entry point (navigation, theme)
assets/                Logo and icon (SVG)
pages/                 UI pages (presentation only)
components/            Reusable UI pieces (theme, cards, charts)
services/              Business logic: email/URL analysis, risk scoring, validation
ml/                    Preprocessing, training, prediction
database/              SQLite persistence for analysis history
config/settings.py     Centralised configuration
scripts/               Data preparation, engine evaluation and demo seeding
docs/                  Project report, architecture, demo guide
data/                  Datasets (raw/processed are git-ignored)
models/                Trained model + metadata
reports/               Evaluation reports
notebooks/             Exploratory data analysis (Jupyter)
tests/                 pytest test suite
```

## Limitations

- The model is trained on public corpora that are partly old. Its test-set metrics measure
  performance on **those corpora**, not guaranteed real-world detection.
- No external reputation service is queried. The URL analysis does not check blacklists.
