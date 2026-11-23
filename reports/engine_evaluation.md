# PhishGuard AI — Full risk engine evaluation

- Model version: `20261123-141729` · evaluated 2026-11-23T14:17:42+00:00
- Held-out test emails: 1506 (never seen during training)
- Settings: ML weight 0.5, Suspicious ≥ 0.4, Likely phishing ≥ 0.7

## Verdicts given by the application

| True class | ✔ Likely legitimate | ⚠ Suspicious | ✖ Likely phishing |
|---|---|---|---|
| Legitimate | 799 | 19 | 0 |
| Phishing | 19 | 271 | 398 |

## Detection metrics (phishing = positive class)

| Decision rule | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Engine: verdict = Likely phishing | 1.0000 | 0.5785 | 0.7330 | 0.0000 |
| Engine: verdict = Suspicious or Likely phishing | 0.9724 | 0.9724 | 0.9724 | 0.0232 |
| AI model alone (probability ≥ 0.5) | 0.9898 | 0.9869 | 0.9884 | 0.0086 |

ROC-AUC — engine score 0.9963, AI probability 0.9993, rule score alone 0.8847.

Mean rule score — legitimate 0.031, phishing 0.430.

Average analysis time: 5.3 ms per email.

## Scope

- The processed dataset keeps only the subject and body (headers and attachments are removed to avoid leakage), so sender-spoofing and attachment indicators cannot fire here: the rules are evaluated on content and link indicators only.
- The engine deliberately needs concrete indicators to say *Likely phishing*, so it trades recall on the 'Likely phishing' verdict for fewer false alarms; emails the model finds suspicious without indicators land in *Suspicious*.
- Same corpus limitations as the model evaluation report apply.
