"""Model evaluation page: real metrics read from the training/evaluation outputs."""

import html

import pandas as pd
import streamlit as st

from components.cards import stat_tile
from components.charts import confusion_heatmap, roc_curve_chart
from components.theme import page_header, verdict_text
from config.settings import get_settings
from services.evaluation import load_evaluation

CHART_CONFIG = {"displayModeBar": False}
ALGO_NAMES = {
    "naive_bayes": "TF-IDF + Multinomial Naive Bayes",
    "linear_svm": "TF-IDF + Linear SVM (calibrated)",
}

settings = get_settings()
data = load_evaluation(settings)

page_header(
    "Model evaluation",
    "How well the AI model and the complete risk engine perform on emails they never saw.",
    eyebrow="Evaluation",
)

if data.model is None:
    st.info(
        "No trained model was found, so there is nothing to evaluate yet. Prepare the data and "
        "train the model, then reload this page:",
        icon="🧪",
    )
    st.code(
        "python -m scripts.prepare_data\npython -m ml.train\npython -m scripts.evaluate_engine",
        language="powershell",
    )
    st.stop()

meta = data.model
m = meta["test_metrics"]
ds = meta["dataset"]
split = meta["split"]
st.caption(
    "All figures on this page are read from `models/model_metadata.json` and "
    "`reports/engine_metrics.json`, produced by the training and evaluation scripts on a "
    "held-out test set. Nothing is hard-coded."
)

# --- Model card ------------------------------------------------------------------
c = st.columns(4)
with c[0]:
    short = {"naive_bayes": "Naive Bayes", "linear_svm": "Linear SVM"}
    stat_tile("Algorithm", short.get(meta["model_name"], meta["model_name"]), meta["algorithm"])
with c[1]:
    stat_tile("Model version", meta["model_version"], f"Trained {meta['created_at'][:10]} (UTC)")
with c[2]:
    stat_tile(
        "Dataset",
        f"{ds['n_total']:,} emails",
        f"{ds['class_counts']['legitimate']:,} legitimate · "
        f"{ds['class_counts']['phishing']:,} phishing",
    )
with c[3]:
    stat_tile(
        "Train / test",
        f"{ds['n_train']:,} / {ds['n_test']:,}",
        f"Test size {split['test_size']:.0%} · seed {split['random_seed']}",
    )

# --- AI model metrics ---------------------------------------------------------
st.markdown("### AI model — held-out test set")
st.caption(
    f"Phishing is the positive class · decision threshold {m['decision_threshold']} · "
    f"{ds['n_test']:,} test emails "
    f"({ds['test_class_counts']['legitimate']:,} legitimate, "
    f"{ds['test_class_counts']['phishing']:,} phishing)."
)
k = st.columns(5)
for col, (label, key) in zip(
    k,
    [
        ("Precision", "precision_phishing"),
        ("Recall", "recall_phishing"),
        ("F1-score", "f1_phishing"),
        ("ROC-AUC", "roc_auc"),
        ("Accuracy", "accuracy"),
    ],
    strict=True,
):
    with col:
        stat_tile(label, f"{m[key]:.3f}")
st.write("")

left, right = st.columns(2, gap="medium")
cm = m["confusion_matrix"]
with left, st.container(border=True):
    st.markdown("**Confusion matrix**")
    st.plotly_chart(
        confusion_heatmap(cm["matrix"], ["Legitimate", "Phishing"], ["Legitimate", "Phishing"]),
        config=CHART_CONFIG,
        width="stretch",
    )
    st.caption(
        f"{cm['false_positive']} legitimate emails flagged as phishing (false positives) · "
        f"{cm['false_negative']} phishing emails missed (false negatives)."
    )
with right, st.container(border=True):
    st.markdown("**ROC curve**")
    roc = m["roc_curve"]
    st.plotly_chart(
        roc_curve_chart(roc["fpr"], roc["tpr"], m["roc_auc"]), config=CHART_CONFIG, width="stretch"
    )

# --- Model selection -----------------------------------------------------------
st.markdown("### Model comparison")
st.caption(
    f"Selection method: {meta['selection']['method']}. The test set was NOT used to choose the "
    "model; its results are shown for comparison only."
)
rows = []
for name, cv in meta["selection"]["cv_results"].items():
    test = meta["comparison_test_metrics"][name]
    rows.append(
        {
            "Model": ALGO_NAMES.get(name, name)
            + (" ✔ selected" if name == meta["model_name"] else ""),
            "CV F1 (mean ± std)": f"{cv['f1_mean']:.4f} ± {cv['f1_std']:.4f}",
            "Test precision": round(test["precision_phishing"], 4),
            "Test recall": round(test["recall_phishing"], 4),
            "Test F1": round(test["f1_phishing"], 4),
            "Test ROC-AUC": round(test["roc_auc"], 4),
        }
    )
st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

# --- Full engine ---------------------------------------------------------------
st.markdown("### Complete risk engine (what the application shows)")
if data.engine is None:
    msg = (
        "The engine evaluation belongs to an older model."
        if data.engine_stale
        else "The complete engine has not been evaluated yet."
    )
    st.info(f"{msg} Run: `python -m scripts.evaluate_engine`", icon="ℹ️")
else:
    e = data.engine
    s = e["settings"]
    st.caption(
        f"The application combines the AI probability with rule-based indicators "
        f"(ML weight {s['ml_weight']}; Suspicious ≥ {s['suspect_threshold']:.0%}, "
        f"Likely phishing ≥ {s['phishing_threshold']:.0%}). Evaluated on the same "
        f"{e['n_test']:,} test emails."
    )
    left, right = st.columns([1.1, 1], gap="medium")
    with left, st.container(border=True):
        st.markdown("**Verdicts given on the test set**")
        st.plotly_chart(
            confusion_heatmap(
                e["verdict_matrix"]["matrix"],
                ["Legitimate", "Phishing"],
                [verdict_text(v) for v in ("legitimate", "suspect", "phishing")],
                height=240,
            ),
            config=CHART_CONFIG,
            width="stretch",
        )
    with right:
        table = []
        for key, label in (
            ("engine_flagged", "Engine: ⚠ Suspicious or ✖ Likely phishing"),
            ("engine_phishing_verdict", "Engine: ✖ Likely phishing only"),
            ("model_only_at_0_5", "AI model alone (≥ 0.5)"),
        ):
            x = e[key]
            table.append(
                {
                    "Decision": label,
                    "Precision": round(x["precision"], 3),
                    "Recall": round(x["recall"], 3),
                    "F1": round(x["f1"], 3),
                    "False-positive rate": f"{x['false_positive_rate']:.1%}",
                }
            )
        st.dataframe(pd.DataFrame(table), hide_index=True, width="stretch")
        st.markdown(
            "**How to read this.** The engine only says *Likely phishing* when concrete "
            "indicators confirm the AI, so that verdict has very few false alarms but misses "
            "phishing that the AI alone would catch: those emails are shown as *Suspicious* "
            "instead. On this test set, from the same era as the training data, the AI alone "
            "scores higher; the rules were added for **modern** legitimate emails (bank and "
            "shop notifications), which these corpora do not contain and on which the AI alone "
            "raises false alarms."
        )
    st.caption(f"Scope: {e['scope_note']} Average analysis time "
               f"{e['seconds_per_email'] * 1000:.1f} ms per email.")  # fmt: skip

# --- Data & method ---------------------------------------------------------------
st.markdown("### Data and method")
left, right = st.columns(2, gap="medium")
with left:
    sources = pd.DataFrame(
        {"Source": list(ds["by_source"]), "Emails": list(ds["by_source"].values())}
    )
    st.dataframe(sources, hide_index=True, width="stretch")
    st.caption(
        "Legitimate: SpamAssassin Public Corpus (ham). Phishing: Nazario Phishing Corpus "
        "(CC BY 4.0, © Jose Nazario)."
    )
with right:
    st.markdown(
        f"""
- **Split:** {html.escape(split["method"])}.
- **Near-duplicate check:** {split["test_subject_overlap_rate"]:.1%} of test emails share a
  subject with a training email.
- **Leakage controls:** headers removed, corpus artifacts scrubbed, duplicates removed before
  the split, TF-IDF fitted on the training set only.
- **Environment:** Python {meta["environment"]["python_version"]},
  scikit-learn {meta["environment"]["sklearn_version"]}.
"""
    )

# --- Influential terms --------------------------------------------------------
st.markdown("### Most influential terms")
left, right = st.columns(2, gap="medium")
for col, key, title in (
    (left, "phishing", "Towards phishing"),
    (right, "legitimate", "Towards legitimate"),
):
    with col:
        st.markdown(f"**{title}**")
        chips = "".join(
            f'<span class="pg-chip">{html.escape(t)}</span>' for t in meta["top_features"][key]
        )
        st.markdown(chips, unsafe_allow_html=True)
st.caption(
    "Placeholders: urltoken = a link, emailtoken = an email address, numtoken = a number. "
    "Some terms reflect the corpora (e.g. Linux mailing lists on the legitimate side) rather "
    "than phishing itself."
)

# --- Limitations -------------------------------------------------------------
st.markdown("### Known limitations")
st.markdown("\n".join(f"- {html.escape(item)}" for item in meta["limitations"]))

with st.expander("Retrain or re-evaluate (administrator)"):
    st.markdown(
        "Training runs from the command line so that it never blocks the interface. "
        "The application reloads the new model automatically."
    )
    st.code(
        "python -m scripts.prepare_data     # rebuild the dataset\n"
        "python -m ml.train                 # train, compare, evaluate, save\n"
        "python -m scripts.evaluate_engine  # evaluate the complete engine",
        language="powershell",
    )
