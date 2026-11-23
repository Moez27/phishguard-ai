# PhishGuard AI — Demonstration guide

A 10–12 minute scenario for the final presentation, using only built-in **synthetic** examples.
Every example uses reserved test domains (`.example`, `203.0.113.0/24`), so nothing shown can
ever point to a real site. All numbers below were produced by the real engine with the current
model (version `20261123-141729`). If you retrain, they may change slightly.

## Before the presentation (5 minutes)

```powershell
cd "path\to\PhishGuard AI"
.\.venv\Scripts\Activate.ps1
pytest -q                                   # show that everything passes (≈ 20 s)
python -m scripts.seed_demo --reset --yes   # clean history + the 8 examples
streamlit run app.py
```

- [ ] The app opens at <http://localhost:8501>. The sidebar shows Dashboard, History, Email analysis, URL analysis and Model evaluation.
- [ ] The Dashboard **Platform status** shows Datasets, ML model and Analysis history as "✔ READY".
- [ ] The browser zoom is at 100–110% and the window is wide (the layout is designed for 1280 px and wider).
- [ ] Close other tabs and turn off notifications.

> `seed_demo` runs every example through the real engine. The records are tagged
> `"source": "demo_example"`, so the dashboard shows real computations, not invented statistics.

## Scenario

### 1. Dashboard (1 min)
- **Show:** KPI tiles (8 analyses, verdict shares), the activity chart, the verdict breakdown, the
  risk distribution with the 40% and 70% thresholds, and the most frequent indicators.
- **Say:** "Every number is computed from the local SQLite history; nothing is hard-coded. Verdicts
  always come with an icon and a label, never colour alone."

### 2. Email: credential phishing (2 min)
Go to **Email analysis**, open **Try a built-in example**, choose *Credential phishing* and click **Analyse email**.

| Expected | Value |
|---|---|
| Verdict | ✖ Likely phishing, **86 / 100** |
| AI probability | 100% |
| Rule-based score | 71% |
| Indicators (5) | Suspicious link, Request for credentials, Urgency, Suspension threat, Generic greeting |

- **Point at:** each indicator's text ("Found: 'verify your identity'"), the words that raised the AI
  score, and the recommendations.
- **Click:** **Download this result (CSV)**.
- **Say:** "The link was never opened. Analysis is offline, and the result says so."

### 3. Email: spoofed sender + attachment, a raw email (1.5 min)
Choose *Spoofed sender + attachment* and analyse it. The pasted text includes the headers.

| Expected | Value |
|---|---|
| Verdict | ✖ Likely phishing, **98 / 100**, **9 indicators** |

- **Point at:**
  - *Link text does not match its real destination*: the link shows paypal.com but leads to 203.0.113.45.
  - *Sender name impersonates a brand*: "PayPal Service" writing from paypa1-support.example.
  - *Replies go to a different domain*.
  - *Potentially dangerous attachment*: `statement.pdf.exe` was identified by its name and **never opened**.

### 4. Email: legitimate messages (1.5 min)
- *Colleague message*: ✔ Likely legitimate, **1 / 100**. Point at the reminder that a low score
  "does not guarantee" safety.
- *Delivery notice*: ✔ Likely legitimate, **23 / 100**. The **AI alone gives 47%**, close to
  its decision threshold. **Explain the design:** "The model was trained on 2002-era legitimate mail
  and is wary of modern notifications. The engine needs concrete indicators to raise an alarm, and
  there are none here, so the verdict stays legitimate."

### 5. URL analysis (1.5 min)
On **URL analysis**, try the examples:

| Example | Expected |
|---|---|
| Brand on look-alike domain | ✖ Likely phishing, 74 |
| Raw IP + executable | ✖ Likely phishing, 72 |
| Credential page with '@' trick | ⚠ Suspicious, 51 |
| Ordinary documentation page | ✔ Likely legitimate, 0 |

- **Point at:** the defanged address (`hxxp://...[.]...`), the *Extracted features* expander, and the
  "not opened, no reputation service" note.
- **Show error handling:** type `javascript:alert(1)`. You get the clear error "Unsupported URL scheme".

### 6. History (1 min)
- **Filter:** verdict = *Likely phishing*, then search `urgency`.
- **Inspect:** tick one row to see its details.
- **Export:** click **Export results (CSV)** and **Export statistics (CSV)**.
- **Say:** "Only minimal data is kept: no email text. Exports are protected against CSV formula
  injection."

### 7. Model evaluation (2 min)
- **Show:** the test-set metrics (precision 0.990, recall 0.987, F1 0.988, ROC-AUC 0.999), the
  confusion matrix (7 false positives, 9 misses) and the ROC curve.
- **Show:** the **model comparison**. The SVM was selected by cross-validation on the training set only.
- **Show:** the **complete engine** table and say it honestly: "On this test set the AI alone scores
  higher. The engine trades some recall for fewer false alarms on modern emails, which these corpora
  do not contain."
- **Show:** the limitations list.

## Likely questions and short answers

| Question | Answer |
|---|---|
| Why are the metrics so high? | The two corpora differ in source and era, so the task is easier than real life. We removed known leakage: headers, the collector's address and mailing-list footers were scrubbed, duplicates were removed before the split, and the split is grouped by subject. Before these fixes, leakage terms were the model's top features. We state that real-world performance may be lower. |
| Why not BERT? | It is an optional extension in the specification. TF-IDF with a linear SVM is fast (about 5 ms per email), explainable term by term, and already strong on these corpora. BERT would add cost and complexity without fixing the main issue, which is dataset bias. |
| Why Naive Bayes vs SVM? | Both were compared with 5-fold cross-validation on the training set. The SVM won (F1 0.986 vs 0.953), mainly through recall: Naive Bayes missed more phishing. |
| How is the score computed? | `max(0.5 × AI + 0.5 × rules, 0.9 × rules)`. The rules are combined with a noisy-OR of hand-set weights. The weights are documented heuristics, not learned. |
| Can it be fooled? | Yes. It is decision support, not a guarantee. A phishing email with no link, no urgency and modern wording may score low. The app always says so. |
| Is it safe to use on real emails? | It never opens links or attachments and stores no email text by default. It listens on localhost only, and inputs are size-limited and protected against ReDoS and injection. |
| Does it check URL reputation? | No. No external service is configured, and the interface says so explicitly. An API is an optional extension (E2), to be added only with a key and the source clearly displayed. |

## If something goes wrong

| Problem | Fix |
|---|---|
| "AI model is not available" | Run `python -m scripts.prepare_data`, then `python -m ml.train`. The page reloads the model automatically. |
| The evaluation page says the engine was not evaluated | `python -m scripts.evaluate_engine` |
| Port 8501 is busy | `streamlit run app.py --server.port 8502` |
| A clean history is needed | `python -m scripts.seed_demo --reset --yes`, or History > Danger zone |
