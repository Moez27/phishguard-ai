# PhishGuard AI — Architecture

## Layers

The code is split into four layers. Each layer only calls the layers below it; the interface
holds no business logic.

```mermaid
flowchart TB
    subgraph UI["Interface — Streamlit (pages/, components/)"]
        D[Dashboard] --- H[History] --- E[Email analysis] --- U[URL analysis] --- M[Model evaluation] --- A[About]
    end
    subgraph S["Business logic (services/)"]
        V[validation] --> EA[email_analyzer]
        V --> UA[url_analyzer]
        EA --> UA
        EA --> R[risk_engine]
        UA --> R
        AN[analysis — facade] --> V
        AN --> R
        HI[history] --> DB
        RP[reports — CSV]
        EV[evaluation]
    end
    subgraph ML["Machine learning (ml/)"]
        P[preprocess] --> DS[dataset] --> T[train]
        T --> PR[predict]
    end
    subgraph DB["Persistence (database/)"]
        REPO[repository] --> SQL[(SQLite<br/>data/phishguard.db)]
    end
    UI --> S
    AN --> PR
    EA --> P
    UI --> REPO
```

| Layer | Folder | Responsibility |
|---|---|---|
| Interface | `app.py`, `pages/`, `components/` | Navigation, theme, display, charts. Calls the services only. |
| Business logic | `services/` | Validation, email and URL indicators, risk scoring, history recording, CSV reports. |
| Machine learning | `ml/` | Parsing and normalisation (shared by training and inference), dataset building, training and evaluation, prediction with integrity check. |
| Persistence | `database/` | SQLite schema and parameterised queries. |
| Configuration | `config/settings.py` | Every tunable value, overridable through `PHISHGUARD_*` environment variables. |
| Scripts | `scripts/` | Command-line tools: data preparation, engine evaluation, demo seeding. |

## Flow of an email analysis

```mermaid
sequenceDiagram
    actor User
    participant Page as pages/email_analysis
    participant Facade as services/analysis
    participant Val as services/validation
    participant Emails as services/email_analyzer
    participant Urls as services/url_analyzer
    participant Model as ml/predict
    participant Risk as services/risk_engine
    participant Hist as services/history
    User->>Page: paste email / upload .txt
    Page->>Facade: run_email_analysis(text)
    Facade->>Val: size, binary, format checks
    Facade->>Emails: extract subject, body, links, sender, attachment names
    Emails->>Urls: analyse each link (offline, never opened)
    Emails-->>Facade: rule indicators
    Facade->>Model: phishing probability + influential terms
    Facade->>Risk: combine → score, verdict, recommendations
    Facade-->>Page: AnalysisResult
    Page->>Hist: record minimal metadata (no email text)
    Page-->>User: verdict, indicators, advice, CSV download
```

## Training pipeline

```mermaid
flowchart LR
    RAW["data/raw/<br/>SpamAssassin ham<br/>Nazario mbox"] --> PREP["scripts/prepare_data<br/>parse · drop headers · scrub artifacts<br/>· deduplicate"]
    PREP --> CSV["data/processed/<br/>emails.csv"]
    CSV --> SPLIT["grouped stratified split<br/>(group = subject, seed 42)"]
    SPLIT --> CV["5-fold group CV on train:<br/>Naive Bayes vs linear SVM"]
    CV --> FIT["refit best on train"]
    FIT --> TEST["single evaluation<br/>on held-out test"]
    TEST --> OUT["models/phishing_model.joblib<br/>models/model_metadata.json<br/>reports/*"]
    OUT --> ENG["scripts/evaluate_engine<br/>(AI + rules on same test set)"]
```

## Risk score

* URL: `risk = rules`, where `rules = 1 − ∏(1 − weightᵢ)` (noisy-OR of the indicator weights).
* Email: `risk = max(w·p_AI + (1 − w)·rules, 0.9·rules)`, with `w = 0.5` by default.
* Verdict: below 0.40 is *Likely legitimate*; 0.40 to 0.70 is *Suspicious*; 0.70 and above is *Likely phishing*.

## Data stored

Table `analyses` (SQLite):

| Column | Notes |
|---|---|
| `public_id`, `created_at` (UTC), `analysis_type`, `verdict` | |
| `risk_score`, `rule_score`, `ml_probability`, `model_version` | Database constraints keep the scores between 0 and 1. |
| `target` | The URL host or the email sender domain. |
| `signal_codes`, `num_signals` | The indicators that fired. |
| `metadata_json`, `duration_ms` | Minimal metadata (counts, flags) and the analysis time. |
| `content` | **NULL** unless `PHISHGUARD_STORE_EMAIL_BODY=true`. |

## Generated artifacts

| File | Produced by | Contents |
|---|---|---|
| `data/processed/emails.csv`, `dataset_stats.json` | `scripts/prepare_data` | The cleaned dataset (git-ignored). |
| `models/phishing_model.joblib` | `ml/train` | The fitted pipeline (git-ignored, regenerated). |
| `models/model_metadata.json`, `reports/metrics.json` | `ml/train` | Version, dataset, split, CV results, test metrics, SHA-256. |
| `reports/evaluation_report.md` | `ml/train` | The model evaluation report. |
| `reports/test_split.json` | `ml/train` | The IDs of the held-out test emails. |
| `reports/engine_metrics.json`, `engine_evaluation.md` | `scripts/evaluate_engine` | The full-engine evaluation. |
| `reports/test_results.txt` | `pytest` (see README) | Test and coverage results. |
