# PhishGuard AI — Project report

*Engineering project in defensive cybersecurity. Project 7: phishing email detection with AI.
Version 1.0.0.*

## 1. Objective

Build a local web platform that analyses emails and URLs, estimates their phishing risk with a
supervised model combined with explainable rules, and provides a dashboard, a history and an
evaluation of the model. The full requirements are in `Cahier_des_charges_PhisGuard_AI.md`.

## 2. Solution overview

| Component | Choice | Why |
|---|---|---|
| Interface | Streamlit (6 pages, dark theme) | Required by the specification; quick to build and to demonstrate. |
| Text model | TF-IDF (1–2-grams) + linear SVM, sigmoid-calibrated | Best cross-validation F1 against Naive Bayes; fast (about 5 ms per email); explainable term by term. |
| Rules | 16 URL indicators and 10 email indicators, combined with a noisy-OR | Explainable, and they compensate for the model's dataset bias. |
| Storage | SQLite, minimal metadata | Local, no server; privacy by default. |
| Charts | Plotly | Hover tooltips; colours checked for colour-blindness. |
| Tests | pytest (210 tests, 94% coverage) and ruff | Required by the specification. |

The architecture is detailed in [ARCHITECTURE.md](ARCHITECTURE.md).

## 3. Data

- **Legitimate emails:** the SpamAssassin Public Corpus `easy_ham`, `easy_ham_2` and `hard_ham` folders (4,150 messages).
- **Phishing emails:** the Nazario Phishing Corpus (CC BY 4.0). We used `phishing2.mbox`, `phishing3.mbox`, `phishing-2024` and `phishing-2025` (4,586 messages). The local antivirus blocked `phishing0.mbox`, `phishing1.mbox` and `phishing-2023` when they were downloaded, so they were not used.
- **Excluded:** SpamAssassin `spam` folders, because generic spam is not phishing.
- **After cleaning:** 7,529 unique emails, 4,091 legitimate (54%) and 3,438 phishing (46%). 1,163 duplicates and 44 empty messages were removed.

### Data leakage found and corrected

The first training run reached F1 0.992, but its strongest features revealed **which corpus**
each email came from rather than whether it was phishing:

| Leaking feature | Origin | Correction |
|---|---|---|
| `monkey`, `jose` → phishing | The collector's address `jose@monkey.org`, inserted by phishing kits | Removed from both classes |
| `mailing list`, `_____`, `url urltoken` → legitimate | SpamAssassin mailing-list footers and RSS gateway lines | Removed |
| 40.7% of test subjects also seen in training | The same campaigns on both sides of the split | Split grouped by subject: now 0% |

Other controls: email headers are discarded, duplicates are removed **before** splitting, and
TF-IDF is fitted on the training set only (inside the scikit-learn pipeline).

## 4. Results (held-out test set: 1,506 emails never seen in training)

**AI model.** It was selected by 5-fold grouped cross-validation on the training set only.

| Model | CV F1 | Test precision | Test recall | Test F1 | ROC-AUC |
|---|---|---|---|---|---|
| Naive Bayes | 0.953 | 0.997 | 0.913 | 0.953 | 0.996 |
| **Linear SVM (selected)** | **0.986** | **0.990** | **0.987** | **0.988** | **0.999** |

The selected model made **7 false positives** (out of 818 legitimate emails) and **9 false negatives** (out of 688 phishing emails).

**The complete engine (what the application shows), on the same test set:**

| Decision | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| ⚠ Suspicious or ✖ Likely phishing | 0.972 | 0.972 | 0.972 | 2.3% |
| ✖ Likely phishing only | 1.000 | 0.578 | 0.733 | 0.0% |

**Interpretation.**
- **The test set favours the AI.** On these corpora the AI alone scores higher than the engine.
- **The engine is cautious by design.** It only says *Likely phishing* when concrete indicators confirm the AI. That verdict raised no false alarm on this test set, but it missed phishing the AI alone would catch; most of those emails (271 of 688) are shown as *Suspicious*, and 19 were rated *Likely legitimate*.
- **The reason for that caution.** In manual checks the AI alone gave a modern bank notification 0.99 and a delivery notice 0.47–0.95, because the legitimate training emails are early-2000s mailing-list messages. The engine keeps such emails out of *Likely phishing* unless indicators are present.
- **No tuning on the test set.** We did not adjust the engine weights on these results, which would be data leakage.

Full reports: `reports/evaluation_report.md` (model) and `reports/engine_evaluation.md` (engine).

## 5. Security

See the README section **Security measures** for the full table. In summary:
- **Links and attachments are never opened.**
- **Minimal storage:** the email text is not stored by default.
- **Local only:** the server listens on localhost.
- **Hardened inputs:** parameterised SQL, escaped HTML, CSV injection protection, a model integrity check, and bounded input sizes.

Two vulnerabilities were found **during the project** and fixed with regression tests:

1. **Regex denial-of-service.** A crafted 50,000-character email took about 14 s to process, about 30 s per analysis. The email-address pattern is now bounded, which brings it down to about 0.2 s.
2. **Network exposure.** Streamlit listens on every network interface by default, so the app was reachable from the local network. It is now bound to localhost.

## 6. Requirements traceability

| Req. | Description | Implementation | Proof |
|---|---|---|---|
| F01 | Dashboard from real data | `pages/dashboard.py` and SQLite statistics | `test_email_analysis_flow_and_dashboard` |
| F02 | Email analysis (paste or `.txt`) | `services/email_analyzer.py`, `pages/email_analysis.py` | `tests/test_email_analyzer.py` |
| F03 | URL analysis (lexical and structural, offline) | `services/url_analyzer.py` | `tests/test_url_analyzer.py` (including the no-network test) |
| F04 | AI classification with probability | `ml/predict.py` (calibrated SVM) | `tests/test_train_predict.py` |
| F05 | Explanations from real features | Indicators and model term contributions | Result page; `test_raw_spoof_signals` |
| F06 | History: search, filter, delete, no body | `pages/history.py`, `database/repository.py` | `tests/test_history_browse.py` |
| F07 | CSV export | `services/reports.py` (history, statistics, single result) | `test_history_csv*`, `test_result_csv` |
| F08 | Evaluation: P, R, F1, confusion matrix, ROC-AUC | `pages/model_evaluation.py` | `tests/test_evaluation.py` |
| F09 | Error handling | `services/validation.py` and page messages | `tests/test_validation.py`, UI error tests |
| CA1 | Starts from the README, no VM | README installation section | Manual check |
| CA2 | Email gives a verdict, score and indicators | Email page | UI test |
| CA3 | URL analysed without opening the site | URL page | No-network test |
| CA4 | Dashboard from stored analyses | Dashboard | UI test |
| CA5 | History filterable and deletable | History page | Repository tests and manual dialog check |
| CA6 | Model evaluated on a separate test set | `ml/train.py` | `reports/evaluation_report.md` |
| CA7 | Invalid input handled cleanly | Validation | 30+ validation tests |
| CA8 | Essential tests and documentation | `tests/`, README, `docs/` | `reports/test_results.txt` |

| Deliverable | Location |
|---|---|
| L1 Source code in Git | This repository |
| L2 Working application | `streamlit run app.py` |
| L3 Data pipeline and training script | `scripts/prepare_data.py`, `ml/train.py` |
| L4 Trained model and metadata | `models/` (the model file is regenerated; the metadata is versioned) |
| L5 Evaluation report | `reports/evaluation_report.md`, `reports/engine_evaluation.md` |
| L6 README | `README.md` |
| L7 Tests and results | `tests/`, `reports/test_results.txt` |
| L8 Presentation and demonstration | `docs/DEMO.md` |

## 7. Limitations

- The corpora are partly old and differ in source and era, so real-world performance is likely below the test-set metrics.
- The legitimate class has a topic bias towards technical mailing lists.
- No URL reputation service is used; detection is lexical and structural only.
- Sender and attachment indicators could not be evaluated quantitatively, because the dataset keeps only the subject and body.
- The rule weights are expert heuristics, not learned.

## 8. Possible extensions

| Extension | Notes |
|---|---|
| Modern legitimate corpus | Would reduce false positives. It needs a dataset not named in the specification. |
| Weights calibrated on a validation split | Learn the AI/rules blend on data separate from the test set. |
| BERT or another transformer (E1) | Possible, but the main limit is the data, not the model. |
| URL reputation API (E2) | Only with a key in `.env` and the source clearly displayed. |
| Secure `.eml` upload (E5) | The parser already handles raw RFC 822 emails. |
| Authentication (E3) and PDF reports (E4) | Optional in the specification. |
