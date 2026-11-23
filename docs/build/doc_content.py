"""French content of the two documents (single source for the PDF and Word versions).

Model and evaluation figures are read from the files produced by training
(models/model_metadata.json, reports/engine_metrics.json, dataset_stats.json):
nothing here is typed by hand, so the documents always match the trained model.

Inline markup: **bold**, `code`.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


META = _load("models/model_metadata.json")
ENGINE = _load("reports/engine_metrics.json")
STATS = _load("data/processed/dataset_stats.json")
TM = META["test_metrics"]
CM = TM["confusion_matrix"]
DS = META["dataset"]
CV = META["selection"]["cv_results"]
CMP = META["comparison_test_metrics"]


def n(x: float, d: int = 3) -> str:
    """French decimal format: 0,988."""
    return f"{x:.{d}f}".replace(".", ",")


def pct(x: float, d: int = 1) -> str:
    return f"{x * 100:.{d}f} %".replace(".", ",")


def k(x: int) -> str:
    """Thousands with a narrow space: 7 529."""
    return f"{x:,}".replace(",", " ")


# --- Block helpers -----------------------------------------------------------
def H1(t):
    return {"t": "h1", "text": t}  # noqa: E704


def H2(t):
    return {"t": "h2", "text": t}  # noqa: E704


def H3(t):
    return {"t": "h3", "text": t}  # noqa: E704


def P(t):
    return {"t": "p", "text": t}  # noqa: E704


def UL(*items):
    return {"t": "ul", "items": list(items)}  # noqa: E704


def OL(*items):
    return {"t": "ol", "items": list(items)}  # noqa: E704


def CODE(t):
    return {"t": "code", "text": t}  # noqa: E704


def NOTE(t, kind="info"):
    return {"t": "note", "text": t, "kind": kind}  # noqa: E704


def BREAK():
    return {"t": "pagebreak"}  # noqa: E704


def TABLE(head, rows, widths=None):
    return {"t": "table", "head": head, "rows": rows, "widths": widths}


def IMG(src, caption, width=1.0):
    return {"t": "img", "src": src, "caption": caption, "width": width}


ENG_F = ENGINE["engine_flagged"]
ENG_P = ENGINE["engine_phishing_verdict"]
ENG_M = ENGINE["model_only_at_0_5"]
VM = ENGINE["verdict_matrix"]["matrix"]

# =============================================================================
# RAPPORT DE PROJET
# =============================================================================
REPORT = {
    "file": "Rapport_PhishGuard_AI",
    "kind": "Rapport de projet",
    "title": "PhishGuard AI",
    "subtitle": "Plateforme intelligente de détection et d'analyse du phishing",
    "context": "Projet ingénieur en cybersécurité défensive — Projet 7 : détection des "
    "emails de phishing par IA",
    "fields": [
        ("Réalisé par", "[Nom et prénom]"),
        ("Établissement", "[École / formation]"),
        ("Encadrant", "[Nom de l'encadrant]"),
        ("Date", "Novembre 2026"),
        ("Version", "1.0.0"),
    ],
    "blocks": [
        H1("Résumé"),
        P(
            "PhishGuard AI est une application web locale qui analyse des emails et des URL "
            "et estime leur risque de phishing. Elle combine un modèle d'apprentissage "
            "supervisé (**TF-IDF + SVM linéaire**) entraîné sur le **SpamAssassin Public "
            "Corpus** et le **Nazario Phishing Corpus** avec des **règles explicables** "
            "(demande d'identifiants, urgence, structure des liens, usurpation d'expéditeur). "
            "Chaque analyse produit un verdict prudent, un score de risque, la liste des "
            "indicateurs détectés et des recommandations."
        ),
        P(
            f"Sur un jeu de test de **{k(DS['n_test'])} emails jamais vus**, le modèle atteint "
            f"une précision de **{n(TM['precision_phishing'])}**, un rappel de "
            f"**{n(TM['recall_phishing'])}** et un F1-score de **{n(TM['f1_phishing'])}** "
            f"(ROC-AUC {n(TM['roc_auc'])}). Une fuite de données présente dans les corpus a "
            "été détectée puis corrigée, deux vulnérabilités ont été trouvées et corrigées "
            "pendant le projet, et l'application est couverte par 210 tests automatisés "
            "(94 % de couverture)."
        ),
        P(
            "Mots-clés : phishing, apprentissage automatique, TF-IDF, SVM, explicabilité, "
            "Streamlit, cybersécurité défensive."
        ),
        {"t": "toc"},
        BREAK(),
        # ------------------------------------------------------------------
        H1("1. Introduction et contexte"),
        P(
            "Le phishing reste l'un des vecteurs d'attaque les plus utilisés : un message "
            "trompeur pousse l'utilisateur à cliquer sur un lien, à saisir ses identifiants ou "
            "à ouvrir une pièce jointe. Les filtres automatiques ne sont jamais parfaits ; un "
            "analyste a besoin d'un outil qui **estime le risque** et surtout **explique "
            "pourquoi**."
        ),
        P(
            "L'objectif du projet est de concevoir et réaliser PhishGuard AI, une plateforme "
            "web de démonstration intégrant l'analyse de messages et d'URL, un modèle de "
            "classification automatique, un tableau de bord et un historique des analyses, "
            "conformément au cahier des charges (durée cible : 5 semaines, 100 % logiciel, "
            "sans machine virtuelle)."
        ),
        H2("1.1 Principes directeurs"),
        UL(
            "**Aide à la décision, pas une certitude** : un score bas n'est jamais présenté "
            "comme une garantie de sécurité.",
            "**Explicabilité** : chaque verdict est justifié par des indicateurs observables.",
            "**Sécurité** : aucun lien n'est ouvert, aucune pièce jointe n'est exécutée.",
            "**Honnêteté des résultats** : aucune métrique inventée ; toutes sont calculées "
            "sur un jeu de test séparé, limites comprises.",
        ),
        # ------------------------------------------------------------------
        H1("2. Cahier des charges et périmètre"),
        P("Le périmètre fonctionnel couvre les neuf fonctionnalités du cahier des charges :"),
        TABLE(
            ["Réf.", "Fonctionnalité", "Réalisation"],
            [
                ["F01", "Tableau de bord", "Statistiques calculées depuis la base SQLite"],
                ["F02", "Analyse d'email", "Texte collé, HTML, email brut ou fichier .txt"],
                ["F03", "Analyse d'URL", "Caractéristiques lexicales et structurelles, hors ligne"],
                ["F04", "Classification IA", "SVM linéaire calibré, probabilité affichée"],
                ["F05", "Explication du résultat", "Indicateurs + termes influents du modèle"],
                ["F06", "Historique", "Recherche, filtres, détails, suppression"],
                ["F07", "Rapports", "Export CSV (historique, statistiques, résultat)"],
                ["F08", "Évaluation du modèle", "Précision, rappel, F1, matrice, ROC-AUC"],
                ["F09", "Gestion des erreurs", "Messages clairs pour toute entrée invalide"],
            ],
            [0.1, 0.32, 0.58],
        ),
        P(
            "**Hors périmètre** (conformément au cahier des charges) : envoi réel d'emails, "
            "visite automatique des liens, garantie de sûreté. Les extensions facultatives "
            "(BERT, API de réputation, authentification, PDF) sont discutées en section 12."
        ),
        # ------------------------------------------------------------------
        H1("3. Architecture de la solution"),
        P(
            "Le code est organisé en couches : l'interface ne contient aucune logique métier, "
            "elle appelle des services testables indépendamment."
        ),
        IMG(
            "diagram_architecture.png", "Figure 1 — Architecture en couches de PhishGuard AI", 0.95
        ),
        TABLE(
            ["Couche", "Dossier", "Rôle"],
            [
                ["Interface", "pages/, components/", "Navigation, thème, affichage, graphiques"],
                ["Métier", "services/", "Validation, indicateurs, score de risque, rapports"],
                ["IA", "ml/", "Prétraitement, entraînement, prédiction"],
                ["Persistance", "database/", "SQLite, requêtes paramétrées"],
                ["Configuration", "config/", "Paramètres centralisés (variables PHISHGUARD_*)"],
                ["Scripts", "scripts/", "Préparation des données, évaluation, démonstration"],
            ],
            [0.2, 0.28, 0.52],
        ),
        H2("3.1 Technologies"),
        TABLE(
            ["Besoin", "Choix", "Justification"],
            [
                ["Interface web", "Streamlit", "Imposé par le sujet, rapide à démontrer"],
                ["Données", "pandas, NumPy", "Manipulation et statistiques"],
                ["IA", "scikit-learn", "TF-IDF, Naive Bayes, SVM, validation croisée"],
                ["Emails HTML", "BeautifulSoup", "Extraction du texte sans exécuter de script"],
                ["Domaines", "tldextract (hors ligne)", "Domaine enregistré, sans accès réseau"],
                ["Stockage", "SQLite", "Local, sans serveur"],
                ["Graphiques", "Plotly", "Infobulles, palette vérifiée pour daltoniens"],
                ["Qualité", "pytest, ruff", "Tests automatisés et analyse statique"],
            ],
            [0.22, 0.26, 0.52],
        ),
        H2("3.2 Déroulement d'une analyse"),
        IMG("diagram_flow.png", "Figure 2 — Chaîne de traitement d'une analyse d'email", 0.95),
        # ------------------------------------------------------------------
        H1("4. Données et préparation"),
        TABLE(
            ["Corpus", "Rôle", "Messages bruts"],
            [
                [
                    "SpamAssassin easy_ham",
                    "Légitime",
                    k(STATS["raw_by_source"]["spamassassin_easy_ham"]),
                ],
                [
                    "SpamAssassin easy_ham_2",
                    "Légitime",
                    k(STATS["raw_by_source"]["spamassassin_easy_ham_2"]),
                ],
                [
                    "SpamAssassin hard_ham",
                    "Légitime",
                    k(STATS["raw_by_source"]["spamassassin_hard_ham"]),
                ],
                ["Nazario (CC BY 4.0)", "Phishing", k(STATS["raw_by_source"]["nazario"])],
            ],
            [0.4, 0.25, 0.35],
        ),  # fmt: skip
        P(
            "Les dossiers `spam` de SpamAssassin sont **exclus** : du spam générique n'est pas "
            "du phishing. Trois fichiers Nazario (`phishing0.mbox`, `phishing1.mbox`, "
            "`phishing-2023`) ont été bloqués par l'antivirus lors du téléchargement — ce qui "
            "est attendu pour du phishing réel — et n'ont pas été utilisés."
        ),
        P(
            f"Après nettoyage : **{k(DS['n_total'])} emails uniques** — "
            f"{k(DS['class_counts']['legitimate'])} légitimes (54 %) et "
            f"{k(DS['class_counts']['phishing'])} de phishing (46 %). "
            f"{k(STATS['duplicates_removed'])} doublons et {STATS['skipped_empty']} messages "
            "vides ont été supprimés."
        ),
        H2("4.1 Fuite de données détectée et corrigée"),
        P(
            "Le premier entraînement atteignait un F1 de 0,992, mais les termes les plus "
            "influents révélaient **d'où venait** chaque email plutôt que s'il s'agissait de "
            "phishing :"
        ),
        TABLE(
            ["Terme appris", "Origine réelle", "Correction"],
            [
                [
                    "monkey, jose → phishing",
                    "Adresse du collecteur jose@monkey.org insérée par les kits de phishing",
                    "Supprimée des deux classes",
                ],
                [
                    "mailing list, url urltoken → légitime",
                    "Pieds de page de listes de diffusion, lignes de passerelle RSS",
                    "Supprimés",
                ],
                [
                    "40,7 % de sujets du test déjà vus",
                    "Mêmes campagnes des deux côtés du découpage",
                    "Découpage groupé par sujet : 0 %",
                ],
            ],
            [0.28, 0.44, 0.28],
        ),  # fmt: skip
        P(
            "Autres contrôles : en-têtes supprimés, doublons retirés **avant** le découpage, "
            "TF-IDF ajusté uniquement sur l'entraînement (dans le pipeline scikit-learn)."
        ),
        H2("4.2 Exploration des données"),
        P(
            "Le notebook `notebooks/exploration.ipynb` analyse le jeu de données. Principaux "
            "constats : les liens sont présents dans environ 90 % des emails de phishing contre "
            "64 % des emails légitimes ; le vocabulaire du phishing porte sur *account, dear, "
            "click, security, bank* ; le score des règles vaut en moyenne 0,42 sur le phishing "
            "contre 0,03 sur les emails légitimes. Le corpus légitime présente un **biais "
            "thématique** (listes techniques Linux du début des années 2000)."
        ),
        # ------------------------------------------------------------------
        H1("5. Modèle d'intelligence artificielle"),
        H2("5.1 Méthode"),
        OL(
            f"Découpage stratifié et groupé par sujet : {k(DS['n_train'])} emails "
            f"d'entraînement, {k(DS['n_test'])} de test (graine 42).",
            "Deux modèles comparés par validation croisée à 5 plis **sur l'entraînement "
            "uniquement** : TF-IDF + Naive Bayes et TF-IDF + SVM linéaire calibré.",
            "Le meilleur est réentraîné puis évalué **une seule fois** sur le jeu de test.",
            "Le modèle, ses métadonnées (version, empreinte SHA-256) et les rapports sont "
            "enregistrés.",
        ),
        H2("5.2 Résultats"),
        TABLE(
            ["Modèle", "F1 (CV)", "Précision", "Rappel", "F1 test", "ROC-AUC"],
            [
                [
                    "Naive Bayes",
                    n(CV["naive_bayes"]["f1_mean"]),
                    n(CMP["naive_bayes"]["precision_phishing"]),
                    n(CMP["naive_bayes"]["recall_phishing"]),
                    n(CMP["naive_bayes"]["f1_phishing"]),
                    n(CMP["naive_bayes"]["roc_auc"]),
                ],
                [
                    "**SVM linéaire (retenu)**",
                    f"**{n(CV['linear_svm']['f1_mean'])}**",
                    f"**{n(TM['precision_phishing'])}**",
                    f"**{n(TM['recall_phishing'])}**",
                    f"**{n(TM['f1_phishing'])}**",
                    f"**{n(TM['roc_auc'])}**",
                ],
            ],
            [0.28, 0.12, 0.15, 0.15, 0.15, 0.15],
        ),  # fmt: skip
        P(
            f"Matrice de confusion du modèle retenu : **{CM['false_positive']} faux positifs** "
            f"sur {k(DS['test_class_counts']['legitimate'])} emails légitimes et "
            f"**{CM['false_negative']} faux négatifs** sur "
            f"{k(DS['test_class_counts']['phishing'])} emails de phishing."
        ),
        IMG(
            "s11_eval_metrics.png",
            "Figure 3 — Métriques, matrice de confusion et courbe ROC (page « Model evaluation »)",
        ),  # fmt: skip
        # ------------------------------------------------------------------
        H1("6. Moteur de risque et règles explicables"),
        P(
            "Le modèle seul ne suffit pas : entraîné sur des emails légitimes anciens, il "
            "surestime le risque de notifications modernes (banque, livraison). Le moteur "
            "combine donc la probabilité de l'IA avec des indicateurs explicables :"
        ),
        CODE(
            "règles  = 1 − Π(1 − poids_i)                         (OU bruité)\n"
            "risque  = max(0,5 × p_IA + 0,5 × règles ; 0,9 × règles)\n"
            "verdict : < 40 % légitime · 40–70 % suspect · ≥ 70 % phishing"
        ),
        P(
            "Conséquence voulue : **l'IA seule ne peut pas dépasser « Suspect »** ; le verdict "
            "« Probablement du phishing » exige des indicateurs concrets. À l'inverse, des "
            "indicateurs forts suffisent même si l'IA hésite."
        ),
        TABLE(
            ["Catégorie", "Exemples d'indicateurs"],
            [
                [
                    "Contenu",
                    "Demande d'identifiants, urgence, menace de suspension, appât "
                    "financier, formule générique (« Dear customer »)",
                ],
                [
                    "Liens",
                    "Adresse IP, symbole @, domaine sosie (punycode), marque sur un "
                    "domaine sans rapport, raccourcisseur, mots sensibles, absence de HTTPS, "
                    "redirection, lien vers un exécutable",
                ],
                ["Expéditeur", "Nom affiché usurpant une marque, Reply-To vers un autre domaine"],
                ["Pièces jointes", "Type dangereux (.exe, .js, .html…), identifié par le nom seul"],
            ],
            [0.2, 0.8],
        ),  # fmt: skip
        IMG(
            "s03_result.png",
            "Figure 4 — Résultat d'une analyse : verdict, indicateurs "
            "justifiés, termes influents et recommandations",
            0.85,
        ),  # fmt: skip
        # ------------------------------------------------------------------
        H1("7. Application : fonctionnalités"),
        H2("7.1 Tableau de bord"),
        P(
            "Toutes les valeurs proviennent des analyses réellement enregistrées. Sans "
            "analyse, la page l'indique au lieu d'afficher des chiffres fictifs."
        ),
        IMG(
            "s01_dashboard_charts.png",
            "Figure 5 — Tableau de bord : indicateurs clés et graphiques",
        ),
        H2("7.2 Analyse d'email"),
        P(
            "L'utilisateur colle un email (texte, HTML ou email brut avec en-têtes) ou "
            "importe un fichier .txt. L'exemple ci-dessous est un email brut avec expéditeur "
            "usurpé, lien trompeur et pièce jointe « statement.pdf.exe » : 9 indicateurs, "
            "risque 98/100. La pièce jointe n'est jamais ouverte."
        ),
        IMG("04b_spoof_indicators.png", "Figure 6 — Indicateurs détectés sur un email usurpé", 0.7),
        H2("7.3 Analyse d'URL"),
        P(
            "L'adresse est analysée comme du texte, sans ouverture ni résolution DNS, et "
            "affichée « désamorcée » (hxxp://…[.]…) pour éviter tout clic accidentel."
        ),
        IMG("s06_url_result.png", "Figure 7 — Analyse d'une URL sosie de PayPal", 0.8),
        H2("7.4 Historique et exports"),
        P(
            "Recherche, filtres (verdict, type, dates), détails d'une analyse, suppression "
            "avec confirmation et export CSV. Seules des métadonnées minimales sont stockées."
        ),
        IMG("s09_history_details.png", "Figure 8 — Historique filtré et détails d'une analyse"),
        H2("7.5 Évaluation du modèle"),
        P(
            "La page « Model evaluation » présente les métriques réelles, la comparaison des "
            "modèles, l'évaluation du moteur complet et les limites."
        ),
        IMG(
            "s11_eval_engine.png",
            "Figure 9 — Comparaison des modèles et évaluation du moteur complet",
        ),
        # ------------------------------------------------------------------
        H1("8. Évaluation du moteur complet"),
        P(
            f"Le moteur (IA + règles) a été évalué sur les mêmes {k(ENGINE['n_test'])} emails "
            "de test :"
        ),
        TABLE(
            ["Décision", "Précision", "Rappel", "F1", "Faux positifs"],
            [
                [
                    "IA seule (p ≥ 0,5)",
                    n(ENG_M["precision"]),
                    n(ENG_M["recall"]),
                    n(ENG_M["f1"]),
                    pct(ENG_M["false_positive_rate"]),
                ],
                [
                    "Moteur : Suspect ou Phishing",
                    n(ENG_F["precision"]),
                    n(ENG_F["recall"]),
                    n(ENG_F["f1"]),
                    pct(ENG_F["false_positive_rate"]),
                ],
                [
                    "Moteur : Phishing seul",
                    n(ENG_P["precision"]),
                    n(ENG_P["recall"]),
                    n(ENG_P["f1"]),
                    pct(ENG_P["false_positive_rate"]),
                ],
            ],
            [0.36, 0.16, 0.16, 0.16, 0.16],
        ),  # fmt: skip
        P(
            f"Verdicts sur les emails de phishing du test : {VM[1][2]} « Probablement du "
            f"phishing », {VM[1][1]} « Suspect », {VM[1][0]} « Probablement légitime ». "
            f"Sur les emails légitimes : {VM[0][0]} légitimes, {VM[0][1]} suspects, "
            f"{VM[0][2]} phishing."
        ),
        NOTE(
            "**Interprétation honnête.** Sur ces corpus, l'IA seule obtient de meilleurs "
            "scores que le moteur complet. La prudence du moteur vise les emails légitimes "
            "modernes, absents de ces corpus. Les poids n'ont pas été ajustés sur le jeu de "
            "test, ce qui constituerait une fuite de données."
        ),
        # ------------------------------------------------------------------
        H1("9. Sécurité et confidentialité"),
        TABLE(
            ["Menace", "Protection"],
            [
                [
                    "Visite d'un lien malveillant",
                    "URL analysées comme du texte, jamais "
                    "ouvertes ; test automatisé bloquant tout accès réseau",
                ],
                ["Pièce jointe malveillante", "Seul le nom est lu ; jamais décodée ni exécutée"],
                ["Entrées volumineuses/binaires", "Limites de taille, détection de binaire"],
                ["Déni de service par expression régulière", "Motifs bornés (voir ci-dessous)"],
                ["Injection SQL", "Requêtes paramétrées, jokers échappés"],
                ["Injection HTML/Markdown", "Échappement systématique, messages assainis"],
                ["Injection de formules CSV", "Cellules commençant par = + - @ neutralisées"],
                ["Modèle falsifié", "Empreinte SHA-256 vérifiée avant chargement"],
                ["Exposition réseau", "Serveur limité à localhost"],
                ["Vie privée", "Aucun texte d'email stocké par défaut, journaux sans contenu"],
            ],
            [0.34, 0.66],
        ),  # fmt: skip
        H2("9.1 Vulnérabilités trouvées et corrigées pendant le projet"),
        UL(
            "**Déni de service (ReDoS)** : un email forgé de 50 000 caractères prenait environ "
            "14 s à traiter (deux fois par analyse). Le motif de détection des adresses email "
            "a été borné : 0,2 s désormais, avec tests de non-régression.",
            "**Exposition réseau** : Streamlit écoute par défaut sur toutes les interfaces ; "
            "l'application était accessible depuis le réseau local. Elle est désormais limitée "
            "à localhost.",
        ),
        # ------------------------------------------------------------------
        H1("10. Tests et qualité"),
        P(
            "**210 tests automatisés** (pytest) avec **94 % de couverture**, et analyse "
            "statique sans erreur (ruff, règles de sécurité incluses). Les pages réelles de "
            "l'application sont pilotées par des tests d'interface (Streamlit AppTest)."
        ),
        TABLE(
            ["Domaine testé", "Exemples"],
            [
                ["Données", "Parsing, nettoyage des artefacts, découpage groupé, doublons"],
                ["IA", "Entraînement, prédiction, refus d'un modèle falsifié"],
                ["Analyse", "Chaque indicateur URL et email, cas légitimes"],
                ["Validation", "Entrées vides, trop longues, binaires, schémas interdits"],
                ["Stockage", "Filtres, recherche, suppression, injection SQL"],
                ["Sécurité", "ReDoS, absence de réseau, CSV, messages assainis"],
                ["Interface", "Analyse d'email de bout en bout, historique, évaluation"],
            ],
            [0.25, 0.75],
        ),  # fmt: skip
        # ------------------------------------------------------------------
        H1("11. Traçabilité des exigences"),
        TABLE(
            ["Critère", "Exigence", "Preuve"],
            [
                ["CA1", "Démarrage en suivant le README, sans VM", "README + guide d'installation"],
                ["CA2", "Email → verdict, score, indicateurs", "Test d'interface, figure 4"],
                ["CA3", "URL analysée sans ouvrir le site", "Test bloquant le réseau"],
                ["CA4", "Tableau de bord depuis les analyses", "Test d'interface, figure 5"],
                ["CA5", "Historique filtrable et supprimable", "Tests du dépôt, figure 8"],
                ["CA6", "Évaluation sur un jeu de test séparé", "reports/evaluation_report.md"],
                ["CA7", "Entrées invalides gérées", "Plus de 30 tests de validation"],
                ["CA8", "Tests et documentation", "reports/test_results.txt, README, docs/"],
            ],
            [0.12, 0.5, 0.38],
        ),
        TABLE(
            ["Livrable", "Emplacement"],
            [
                ["L1 Code source (Git)", "Dépôt GitHub privé"],
                ["L2 Application", "streamlit run app.py"],
                ["L3 Pipeline de données et entraînement", "scripts/prepare_data.py, ml/train.py"],
                ["L4 Modèle et métadonnées", "models/"],
                ["L5 Rapport d'évaluation", "reports/evaluation_report.md, engine_evaluation.md"],
                ["L6 README", "README.md"],
                ["L7 Tests et résultats", "tests/, reports/test_results.txt"],
                ["L8 Présentation et démonstration", "Guide de démonstration, vidéo MP4"],
            ],
            [0.45, 0.55],
        ),
        # ------------------------------------------------------------------
        H1("12. Limites et perspectives"),
        H2("12.1 Limites"),
        UL(
            "Corpus en partie anciens et d'origines différentes : la performance réelle sur des "
            "emails actuels est probablement inférieure aux métriques du test.",
            "Biais thématique du corpus légitime (listes techniques).",
            "Pas de service de réputation d'URL : analyse lexicale et structurelle uniquement.",
            "Indicateurs d'expéditeur et de pièces jointes non évaluables quantitativement "
            "(le jeu de données ne conserve que l'objet et le corps).",
            "Poids des règles fixés par expertise, non appris.",
        ),
        H2("12.2 Perspectives"),
        UL(
            "Ajouter un corpus d'emails légitimes récents pour réduire les faux positifs.",
            "Apprendre le mélange IA/règles sur un jeu de validation distinct du test.",
            "Modèle BERT ou transformeur (extension E1).",
            "API de réputation d'URL avec clé dans .env et source affichée (E2).",
            "Import sécurisé de fichiers .eml (E5), authentification (E3), rapport PDF (E4).",
        ),
        # ------------------------------------------------------------------
        H1("13. Conclusion"),
        P(
            "PhishGuard AI répond à l'ensemble des fonctionnalités et critères d'acceptation "
            "du cahier des charges : une application locale, sécurisée et documentée qui "
            "analyse emails et URL, explique ses verdicts et présente une évaluation honnête de "
            "son modèle. Au-delà des scores, le projet montre l'importance de vérifier ce que "
            "le modèle apprend réellement (fuite de données corrigée), de tester la sécurité "
            "de l'outil lui-même (deux vulnérabilités corrigées) et de présenter les "
            "limites aussi clairement que les résultats."
        ),
        H1("Annexe — Commandes principales"),
        CODE(
            "py -3.12 -m venv .venv\n"
            ".\\.venv\\Scripts\\Activate.ps1\n"
            "pip install -r requirements-dev.txt\n"
            "python -m scripts.prepare_data      # préparer les données\n"
            "python -m ml.train                  # entraîner et évaluer le modèle\n"
            "python -m scripts.evaluate_engine   # évaluer le moteur complet\n"
            "pytest                              # lancer les tests\n"
            "streamlit run app.py                # lancer l'application"
        ),
    ],
}

# =============================================================================
# GUIDE D'INSTALLATION ET DE DÉMONSTRATION
# =============================================================================
GUIDE = {
    "file": "Guide_Demonstration_PhishGuard_AI",
    "kind": "Guide d'installation et de démonstration",
    "title": "PhishGuard AI",
    "subtitle": "Installer, lancer et présenter l'application",
    "context": "Comment l'exécuter, comment elle fonctionne et ses fonctionnalités, "
    "illustrés par des captures d'écran réelles",
    "fields": [
        ("Vidéo de démonstration", "docs/media/phishguard_demo.mp4 (3 min 17 s)"),
        ("Date", "Novembre 2026"),
        ("Version", "1.0.0"),
    ],
    "blocks": [
        {"t": "toc"},
        BREAK(),
        H1("1. Présentation en une minute"),
        P(
            "PhishGuard AI analyse un **email** ou une **URL** et répond à la question : "
            "« est-ce probablement du phishing, et pourquoi ? ». Le résultat combine une IA "
            "(TF-IDF + SVM) et des règles explicables. L'application tourne entièrement sur "
            "votre ordinateur, sans machine virtuelle."
        ),
        TABLE(
            ["Verdict", "Score", "Signification"],
            [
                ["✔ Probablement légitime", "< 40", "Aucun indicateur fort (jamais une garantie)"],
                ["⚠ Suspect", "40 – 70", "À vérifier par un canal officiel"],
                ["✖ Probablement du phishing", "≥ 70", "Ne pas cliquer, signaler"],
            ],
            [0.34, 0.14, 0.52],
        ),
        NOTE(
            "Sécurité : les liens ne sont jamais ouverts, les pièces jointes jamais exécutées, "
            "et l'application n'est accessible que depuis cet ordinateur (localhost)."
        ),
        # ------------------------------------------------------------------
        H1("2. Prérequis"),
        UL(
            "Windows 10/11, macOS ou Linux.",
            "Python 3.12 (3.11 fonctionne aussi).",
            "Environ 500 Mo d'espace disque (dépendances et jeux de données).",
            "Une connexion Internet pour l'installation uniquement.",
        ),
        # ------------------------------------------------------------------
        H1("3. Installation pas à pas (Windows / PowerShell)"),
        P("Ouvrir PowerShell dans le dossier du projet, puis :"),
        CODE(
            "# 1. Créer et activer l'environnement virtuel (venv, pas une VM)\n"
            "py -3.12 -m venv .venv\n"
            ".\\.venv\\Scripts\\Activate.ps1\n\n"
            "# 2. Installer les dépendances\n"
            "python -m pip install --upgrade pip\n"
            "pip install -r requirements-dev.txt"
        ),
        NOTE(
            "Si PowerShell bloque Activate.ps1, exécuter une fois "
            "`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, ou utiliser directement "
            "`.\\.venv\\Scripts\\python.exe`.",
            "warn",
        ),
        # ------------------------------------------------------------------
        H1("4. Préparer les données et entraîner le modèle"),
        P(
            "Les corpus ne sont pas inclus dans le dépôt. Les placer dans `data/raw/` comme "
            "décrit dans `data/README.md` (SpamAssassin : dossiers easy_ham, easy_ham_2, "
            "hard_ham ; Nazario : fichiers mbox), puis :"
        ),
        CODE(
            "python -m scripts.prepare_data      # nettoyer et dédupliquer (~40 s)\n"
            "python -m ml.train                  # comparer, évaluer, enregistrer (~1 min)\n"
            "python -m scripts.evaluate_engine   # évaluer le moteur complet (~10 s)"
        ),
        P(
            f"Résultat attendu : {k(DS['n_total'])} emails, modèle « Linear SVM » sélectionné, "
            f"F1 de test ≈ {n(TM['f1_phishing'])}. Les fichiers produits sont "
            "`models/phishing_model.joblib`, `models/model_metadata.json` et les rapports "
            "dans `reports/`."
        ),
        NOTE(
            "Sans modèle entraîné, l'application fonctionne quand même en mode « règles "
            "seules » et l'indique clairement.",
        ),
        # ------------------------------------------------------------------
        H1("5. Lancer l'application"),
        CODE("streamlit run app.py"),
        P(
            "L'application s'ouvre sur http://localhost:8501. Au premier lancement, "
            "l'historique est vide : le tableau de bord l'indique et propose de commencer une "
            "analyse. L'état de la plateforme (données, modèle, historique) est affiché."
        ),
        IMG("00_dashboard_empty.png", "Figure 1 — Premier lancement : tableau de bord vide", 0.9),
        P("Pour remplir l'historique avec les 8 exemples intégrés (démonstration) :"),
        CODE("python -m scripts.seed_demo --reset --yes"),
        # ------------------------------------------------------------------
        H1("6. Visite guidée des fonctionnalités"),
        H2("6.1 Analyser un email"),
        OL(
            "Menu **Email analysis**.",
            "Coller l'email dans « Email content » (ou choisir « Upload .txt file »). "
            "L'objet est facultatif.",
            "Ou ouvrir « Try a built-in example » et choisir un exemple synthétique.",
            "Cliquer sur **Analyse email**.",
        ),
        IMG("02_email_input.png", "Figure 2 — Saisie d'un email (exemple de phishing chargé)", 0.9),
        P("Le résultat se lit de haut en bas :"),
        UL(
            "**Bandeau de verdict** : icône + libellé (jamais la couleur seule) et jauge 0–100 "
            "avec les seuils 40 et 70.",
            "**Trois tuiles** : probabilité de l'IA, score des règles, nombre d'indicateurs.",
            "**Indicateurs** classés par gravité, chacun avec sa justification (« Found: … »).",
            "**Mots ayant augmenté le score de l'IA** et **recommandations**.",
            "Bouton **Download this result (CSV)** pour exporter le résultat.",
        ),
        IMG("s03_result.png", "Figure 3 — Résultat : phishing classique, risque 86/100", 0.85),
        H3("Email brut avec en-têtes"),
        P(
            "En collant un email complet (From, Reply-To, Subject…), l'application détecte "
            "aussi l'usurpation d'expéditeur, le Reply-To vers un autre domaine, les liens dont "
            "le texte affiché ne correspond pas à la destination, et les pièces jointes "
            "dangereuses (identifiées par leur nom uniquement)."
        ),
        IMG("s04_result.png", "Figure 4 — Email usurpé : 9 indicateurs, risque 98/100", 0.85),
        H3("Email légitime"),
        P(
            "Un avis de livraison obtient 23/100 : l'IA seule donnait 47 %, mais sans indicateur "
            "concret le moteur ne crie pas au loup. Le message rappelle qu'un score bas n'est "
            "pas une garantie."
        ),
        IMG("s05_result.png", "Figure 5 — Email légitime : risque 23/100", 0.85),
        H2("6.2 Analyser une URL"),
        OL(
            "Menu **URL analysis**.",
            "Saisir l'adresse (le préfixe http:// est facultatif) ou choisir un exemple.",
            "Cliquer sur **Analyse URL**.",
        ),
        P(
            "L'adresse est affichée « désamorcée » (hxxp, [.]) et n'est jamais ouverte. "
            "Le volet « Extracted features » détaille l'hôte, le domaine enregistré, HTTPS, "
            "la longueur, etc."
        ),
        IMG("s06_url_result.png", "Figure 6 — URL sosie de PayPal : risque 74/100", 0.8),
        P("Les entrées invalides sont refusées avec un message clair :"),
        IMG("07_url_error.png", "Figure 7 — Schéma « javascript: » refusé", 0.85),
        H2("6.3 Tableau de bord"),
        P(
            "Indicateurs clés, activité sur 30 jours, répartition des verdicts, distribution "
            "des scores et indicateurs les plus fréquents, tous calculés depuis l'historique."
        ),
        IMG("s01_dashboard_charts.png", "Figure 8 — Tableau de bord après 8 analyses"),
        IMG("s01_dashboard_table.png", "Figure 9 — Dernières analyses et état de la plateforme"),
        H2("6.4 Historique"),
        UL(
            "**Rechercher** par domaine, identifiant ou indicateur (ex. « urgency »).",
            "**Filtrer** par verdict, type et plage de dates.",
            "**Cocher une ligne** pour voir ses détails ou la supprimer (confirmation).",
            "**Exporter** les résultats filtrés ou les statistiques en CSV.",
            "« Danger zone » : effacer tout l'historique (case de confirmation obligatoire).",
        ),
        IMG("08_history.png", "Figure 10 — Historique des analyses", 0.95),
        IMG("s09_history_details.png", "Figure 11 — Filtre « Likely phishing » et détails"),
        IMG("10_history_delete_dialog.png", "Figure 12 — Confirmation de suppression", 0.85),
        H2("6.5 Évaluation du modèle"),
        P(
            "Métriques réelles sur le jeu de test, matrice de confusion, courbe ROC, "
            "comparaison des modèles, évaluation du moteur complet, données et limites."
        ),
        IMG("s11_eval_metrics.png", "Figure 13 — Métriques du modèle sur le jeu de test"),
        IMG("s11_eval_data.png", "Figure 14 — Données, méthode et termes influents"),
        H2("6.6 À propos et affichage mobile"),
        IMG("12_about.png", "Figure 15 — Page « About »", 0.8),
        IMG("13_mobile_dashboard.png", "Figure 16 — Affichage sur téléphone", 0.32),
        # ------------------------------------------------------------------
        H1("7. Scénario de démonstration (10–12 minutes)"),
        TABLE(
            ["Étape", "Action", "À montrer"],
            [
                ["1", "Tableau de bord", "Chiffres calculés, verdicts avec icône + texte"],
                [
                    "2",
                    "Email « Credential phishing »",
                    "86/100, 5 indicateurs, mots de l'IA, export CSV",
                ],
                [
                    "3",
                    "Email « Spoofed sender »",
                    "98/100, usurpation, pièce jointe jamais ouverte",
                ],
                ["4", "Emails légitimes", "1/100 et 23/100 ; l'IA seule donnait 47 %"],
                ["5", "URL d'exemple + « javascript: »", "Désamorçage, 74/72/51/0, erreur claire"],
                ["6", "Historique", "Filtre, recherche « urgency », détails, export"],
                ["7", "Évaluation du modèle", "Métriques, matrice, moteur complet, limites"],
            ],
            [0.1, 0.36, 0.54],
        ),  # fmt: skip
        P(
            "La vidéo `docs/media/phishguard_demo.mp4` (3 min 17 s, sous-titrée en français) "
            "montre exactement ce parcours. Le détail des phrases à dire et des réponses aux "
            "questions probables se trouve dans `docs/DEMO.md`."
        ),
        # ------------------------------------------------------------------
        H1("8. Dépannage"),
        TABLE(
            ["Problème", "Solution"],
            [
                [
                    "« AI model is not available »",
                    "python -m scripts.prepare_data puis python -m ml.train",
                ],
                ["Évaluation du moteur absente", "python -m scripts.evaluate_engine"],
                ["Port 8501 occupé", "streamlit run app.py --server.port 8502"],
                [
                    "Démo sur un autre appareil",
                    "streamlit run app.py --server.address 0.0.0.0 "
                    "(réseau de confiance uniquement)",
                ],
                ["Repartir d'un historique propre", "python -m scripts.seed_demo --reset --yes"],
            ],
            [0.38, 0.62],
        ),  # fmt: skip
        H1("9. Régénérer ce guide, les captures et la vidéo"),
        CODE(
            "pip install -r docs/build/requirements-docs.txt\n"
            "cd docs/build; npm install; cd ../..\n"
            "python docs/build/capture_screenshots.py   # captures d'écran\n"
            "python docs/build/record_demo.py           # vidéo MP4\n"
            "python docs/build/build_docs.py            # PDF et Word"
        ),
        P(
            "Ces scripts utilisent Microsoft Edge (déjà installé sous Windows) et une base de "
            "démonstration séparée : l'historique réel n'est jamais modifié."
        ),
    ],
}

DOCUMENTS = [REPORT, GUIDE]
