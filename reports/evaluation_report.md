# PhishGuard AI — Model evaluation report

- **Model version:** `20261123-141729`
- **Algorithm:** TF-IDF + Linear SVM (sigmoid-calibrated)
- **Trained at (UTC):** 2026-11-23T14:17:29+00:00
- **scikit-learn:** 1.9.1

## Dataset

- Sources: nazario (3438), spamassassin_easy_ham (2464), spamassassin_easy_ham_2 (1387), spamassassin_hard_ham (240)
- Total after deduplication: 7529 (legitimate 4091, phishing 3438)
- Train / test: 6023 / 1506
- Split: stratified group split (group = normalised subject) after exact-duplicate removal, test size 0.2, seed 42
- Test emails whose subject also appears in train (near-duplicate indicator): 0.0%

## Model selection (cross-validation on the training set only)

| Model | CV F1 (mean ± std) | CV precision | CV recall |
|---|---|---|---|
| TF-IDF + Multinomial Naive Bayes | 0.9533 ± 0.0063 | 0.9964 | 0.9138 |
| TF-IDF + Linear SVM (sigmoid-calibrated) | 0.9862 ± 0.0030 | 0.9880 | 0.9844 |

Selected: **TF-IDF + Linear SVM (sigmoid-calibrated)** (highest mean CV F1).

## Held-out test set results (threshold 0.5)

| Metric | Value |
|---|---|
| Precision (phishing) | 0.9898 |
| Recall (phishing) | 0.9869 |
| F1-score (phishing) | 0.9884 |
| Accuracy | 0.9894 |
| ROC-AUC | 0.9993 |
| Average precision | 0.9993 |

Confusion matrix (rows = true class, columns = predicted class):

| | Predicted legitimate | Predicted phishing |
|---|---|---|
| **True legitimate** | 811 | 7 |
| **True phishing** | 9 | 679 |

## Test-set results of every candidate (for comparison only, not for selection)

| Model | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| TF-IDF + Multinomial Naive Bayes | 0.9968 | 0.9128 | 0.9530 | 0.9959 |
| TF-IDF + Linear SVM (sigmoid-calibrated) | 0.9898 | 0.9869 | 0.9884 | 0.9993 |

## Most influential terms

- Towards phishing: account, your, ebay, bank, she, he, urltoken, please, annie, security, you, her, important, customer, pharmacy, notification, paypal, confirmation, fifth third, third bank, bb, banking, dear, online, fifth
- Towards legitimate: the, re, wrote, on, my, is, numtoken urltoken, that, news, it, img urltoken, to, razor, some, linux, list, in, world, for, spamassassin, of, so, users, at, emailtoken

## Known limitations

- Legitimate and phishing emails come from different corpora, periods and collection methods; part of the measured performance may reflect these differences rather than phishing itself. Known collection artifacts (collector address/domain, mailing-list footers, RSS gateway lines) are removed, but topic differences remain: the legitimate class is dominated by early-2000s tech mailing lists (Linux, RPM, SpamAssassin).
- SpamAssassin ham dates from around 2002-2005; current legitimate emails (e.g. modern transactional emails from banks or online shops) are under-represented, so false positives on such emails are likely to be higher than the test set suggests.
- Emails sharing a subject are kept on the same side of the split to limit campaign leakage, but near-duplicates with different subjects can still cross the split.
- Recent phishing samples include 'hash-busting' filler text (e.g. novel excerpts) whose words the model may associate with phishing.
- Test-set metrics describe performance on these corpora only, not guaranteed real-world detection on today's emails.
- The probability is a model estimate, not a certainty. A low score never proves an email is safe.
