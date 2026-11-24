"""Build the PhishGuard AI cahier des charges on the provided Word model.

    .\\.venv\\Scripts\\python.exe docs\\build\\build_cahier.py

The model (docs/Cahier_des_charges_Projet_IDPS_Machine_Learning.docx) is reused
as is: styles, theme, numbering, page size, header/footer. Only the body is
regenerated with the same XML patterns (cover, Heading1/2/3, ListBullet,
ListNumber, "LightShading-Accent1" tables) and the content of PhishGuard AI.
Changes from the model: header text, second numbered list restarts at 1, the
model's preview thumbnail (which shows the IDPS document) is removed.

Outputs: docs/Cahier_des_charges_PhishGuard_AI.docx and .pdf (PDF exported by
Microsoft Word, so it looks exactly like the Word file).
"""

from __future__ import annotations

import re
import subprocess
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "docs" / "Cahier_des_charges_Projet_IDPS_Machine_Learning.docx"
OUT_DOCX = ROOT / "docs" / "Cahier_des_charges_PhishGuard_AI.docx"
OUT_PDF = OUT_DOCX.with_suffix(".pdf")

HEADER_TEXT = "PROJET DE CYBERSÉCURITÉ | IA &amp; DÉTECTION DU PHISHING"
NUMBER_ABSTRACT_ID = "7"  # abstract list behind the ListNumber style (numId 5)

# =============================================================================
# Content (same structure and tone as the model)
# =============================================================================
COVER_LINES = [
    "Projet de cybersécurité :",
    "Détection des emails de phishing",
    "par Intelligence Artificielle — PhishGuard AI",
]
COVER_NOTE = "Document destiné aux étudiants en cycle ingénieur"

CONTENT = [
    ("h1", "Présentation générale du projet"),
    ("p", "Ce projet consiste à concevoir, développer et évaluer une plateforme intelligente de "
          "détection et d'analyse du phishing, PhishGuard AI, capable d'analyser des emails et des "
          "URL et d'estimer leur niveau de risque, en utilisant des algorithmes de Machine Learning "
          "(Naive Bayes, SVM, BERT) et des règles explicables."),
    ("p", "L'objectif est de mettre en pratique les connaissances en cybersécurité, en intelligence "
          "artificielle et en programmation Python, depuis la compréhension des techniques de "
          "phishing jusqu'à la mise en place d'une application web de détection, d'explication et "
          "de suivi des analyses."),

    ("h1", "1. Introduction"),
    ("p", "Présenter le contexte général du projet et expliquer :"),
    ("ul", ["Qu'est-ce que le phishing et en quoi diffère-t-il du spear phishing ?",
            "Pourquoi l'email reste-t-il l'un des principaux vecteurs de cyberattaques ?",
            "Quel est le rôle de l'intelligence artificielle dans la détection du phishing ?",
            "Pourquoi combiner un modèle d'IA avec des règles explicables pour estimer le risque ?"]),
    ("p", "L'introduction doit permettre de comprendre le contexte et l'intérêt du projet."),

    ("h1", "2. Problématique"),
    ("p", "Les étudiants doivent identifier et expliquer le problème auquel leur projet cherche à "
          "répondre."),
    ("p", "Exemples de questions à traiter :"),
    ("ul", ["Comment détecter automatiquement un email de phishing ?",
            "Comment distinguer un email légitime d'un email frauduleux qui imite une marque connue ?",
            "Comment repérer une URL malveillante sans l'ouvrir ?",
            "Comment détecter l'usurpation de l'identité de l'expéditeur ?",
            "Comment réduire les faux positifs sur les emails légitimes ?",
            "Comment expliquer le verdict à l'utilisateur de façon compréhensible ?"]),
    ("p", "Il faut expliquer les limites des solutions traditionnelles (listes noires, filtres par "
          "mots-clés) et montrer l'intérêt d'une approche basée sur l'intelligence artificielle "
          "complétée par des règles explicables."),

    ("h1", "3. Objectifs du projet"),
    ("p", "Les principaux objectifs sont les suivants :"),
    ("ol", ["Identifier et comprendre les menaces étudiées : phishing, spear phishing simulé, URL "
            "malveillantes et usurpation d'expéditeur.",
            "Étudier les indicateurs qui caractérisent un email ou une URL de phishing.",
            "Constituer un dataset à partir du SpamAssassin Public Corpus et du Nazario Phishing "
            "Corpus.",
            "Développer des modèles de Machine Learning pour classer les emails.",
            "Comparer les performances de plusieurs algorithmes (Naive Bayes, SVM, BERT en "
            "extension).",
            "Sélectionner le meilleur modèle selon les résultats expérimentaux.",
            "Intégrer le modèle sélectionné dans une application web (Streamlit) d'analyse d'emails "
            "et d'URL.",
            "Produire un score de risque, des explications et des recommandations, avec un "
            "historique et un tableau de bord."]),

    ("h1", "4. Solutions proposées et implémentation"),
    ("p", "Cette partie constitue le cœur technique du projet. Elle doit présenter le travail "
          "réalisé par les étudiants."),
    ("h2", "4.1. Présentation des menaces étudiées"),
    ("p", "Les étudiants doivent étudier les menaces de phishing suivantes et les illustrer par des "
          "exemples."),
    ("p", "Menaces :"),
    ("ul", ["Phishing classique : email générique imitant une banque ou un service en ligne.",
            "Spear phishing (simulé) : email ciblé et personnalisé pour une victime précise.",
            "URL malveillantes : domaines sosies, adresses IP, raccourcisseurs, redirections.",
            "Usurpation d'expéditeur : nom affiché trompeur, adresse de réponse (Reply-To) "
            "différente."]),
    ("p", "Pour chaque menace, les étudiants doivent présenter :"),
    ("ul", ["Son principe de fonctionnement et son objectif.",
            "Ses conséquences pour la victime (vol d'identifiants, fraude, infection).",
            "Un exemple dans un environnement contrôlé (exemples synthétiques, domaines fictifs, "
            "aucun envoi réel).",
            "Les indicateurs permettant de la détecter."]),
    ("h2", "4.2. Présentation des outils utilisés"),
    ("p", "Les outils du projet sont Python, Scikit-learn, BeautifulSoup, Streamlit et Jupyter. "
          "Les étudiants doivent présenter :"),
    ("ul", ["L'architecture générale de l'application et ses différents composants.",
            "Le rôle de chaque outil (traitement des emails, apprentissage, interface, analyse).",
            "Le traitement d'un email : extraction du texte, des liens et des caractéristiques.",
            "Les raisons du choix de ces outils."]),
    ("p", "Une étude comparative peut être réalisée avec des solutions existantes, par exemple les "
          "filtres anti-spam (SpamAssassin) ou les services de réputation d'URL, afin de "
          "positionner la solution PhishGuard AI."),
    ("h2", "4.3. Constitution et préparation du dataset"),
    ("p", "Les étudiants doivent utiliser des données pour entraîner et tester leurs modèles "
          "d'intelligence artificielle. Deux sources sont proposées :"),
    ("h3", "A. SpamAssassin Public Corpus"),
    ("p", "Utiliser les emails légitimes (ham) de ce corpus public, par exemple :"),
    ("ul", ["Emails « easy ham » : messages légitimes faciles à classer.",
            "Emails « hard ham » : messages légitimes proches du spam.",
            "Extraction de l'objet et du corps des messages.",
            "Exclusion du spam générique, qui n'est pas du phishing."]),
    ("h3", "B. Nazario Phishing Corpus"),
    ("p", "Utiliser les emails de phishing réels de ce corpus public (format mbox), en vérifiant "
          "ses conditions d'utilisation."),
    ("p", "Dans les deux cas, les étudiants doivent présenter :"),
    ("ul", ["La source du dataset et ses conditions d'utilisation (licence).",
            "Le nombre d'échantillons et les caractéristiques (features) extraites.",
            "Les classes disponibles (légitime, phishing) et leur répartition.",
            "Les étapes de nettoyage et de prétraitement (texte, URL, suppression des doublons).",
            "La séparation des données d'entraînement et de test, sans fuite de données."]),
    ("h2", "4.4. Application des algorithmes de Machine Learning"),
    ("p", "Les étudiants doivent étudier deux grandes catégories d'algorithmes :"),
    ("h3", "A. Modèles classiques (apprentissage supervisé)"),
    ("p", "Le modèle apprend à partir d'emails étiquetés (labeled data), dont le texte est "
          "transformé en vecteurs TF-IDF. Exemples d'algorithmes :"),
    ("ul", ["Naive Bayes (Multinomial)",
            "Support Vector Machine (SVM)",
            "Logistic Regression",
            "Random Forest"]),
    ("p", "Objectif : apprendre à reconnaître les différentes classes, par exemple les emails "
          "légitimes et les emails de phishing."),
    ("h3", "B. Modèles de langage (Deep Learning, extension)"),
    ("p", "Le modèle pré-entraîné est affiné sur les emails étiquetés. Exemples de modèles :"),
    ("ul", ["BERT", "DistilBERT", "RoBERTa"]),
    ("p", "Objectif : mieux comprendre le contexte et le sens des messages, au prix d'un coût de "
          "calcul plus élevé."),
    ("h2", "4.5. Comparaison et sélection du meilleur modèle"),
    ("p", "Les algorithmes doivent être évalués et comparés à l'aide de métriques pertinentes."),
    ("table", [["Métrique", "Signification"],
               ["Accuracy", "Taux de bonnes prédictions."],
               ["Precision", "Proportion d'emails signalés comme phishing qui le sont réellement."],
               ["Recall", "Capacité à détecter les emails de phishing."],
               ["F1-score", "Équilibre entre Precision et Recall."],
               ["False Positive Rate", "Taux d'emails légitimes signalés à tort."],
               ["ROC-AUC", "Capacité du modèle à séparer les deux classes."],
               ["Temps d'analyse", "Temps nécessaire pour analyser un email."]]),
    ("p", "Les résultats doivent être présentés sous forme de tableaux et de graphiques, avec la "
          "matrice de confusion. À la fin de cette étude, les étudiants doivent sélectionner le "
          "meilleur modèle en justifiant leur choix à partir des résultats expérimentaux."),
    ("p", "Attention : le modèle ayant la meilleure Accuracy n'est pas nécessairement le meilleur "
          "modèle pour la cybersécurité. Un faux négatif laisse passer un phishing, un faux positif "
          "bloque un email légitime : le Recall et le taux de faux positifs sont essentiels."),
    ("h2", "4.6. Intégration du modèle dans l'application PhishGuard AI"),
    ("p", "Après avoir sélectionné le meilleur modèle, les étudiants doivent l'intégrer dans "
          "l'application web PhishGuard AI. Deux mécanismes doivent être présentés :"),
    ("boxes", ("Analyse et détection",
               ["Analyser un email ou une URL.",
                "Extraire les liens et les caractéristiques.",
                "Calculer la probabilité de phishing.",
                "Classer : légitime, suspect, phishing.",
                "Enregistrer l'analyse dans l'historique."],
               "Explication et aide à la décision",
               ["Afficher un score de risque.",
                "Présenter les indicateurs détectés.",
                "Donner des recommandations prudentes.",
                "Suivre les analyses (dashboard, CSV).",
                "Ne jamais ouvrir les liens ni les pièces jointes."])),
    ("p", "L'intégration doit permettre de démontrer le fonctionnement global du système : "
          "lorsqu'un email ou une URL est analysé, le modèle estime le risque et l'application "
          "explique le verdict par des indicateurs concrets, sans jamais le présenter comme une "
          "certitude."),

    ("h1", "5. Conclusion"),
    ("p", "Présenter un bilan du travail réalisé, notamment :"),
    ("ul", ["Les menaces de phishing étudiées.",
            "Le dataset constitué et les prétraitements appliqués.",
            "Les algorithmes développés.",
            "Les résultats de la comparaison.",
            "Le modèle sélectionné.",
            "Les performances de l'application PhishGuard AI.",
            "Les limites de la solution proposée."]),

    ("h1", "6. Perspectives"),
    ("p", "Proposer des améliorations possibles, par exemple :"),
    ("ul", ["Utilisation de modèles de langage (BERT) pour mieux comprendre les messages.",
            "Connexion à une API de réputation d'URL.",
            "Import sécurisé de fichiers .eml.",
            "Ajout de corpus d'emails récents pour réduire les faux positifs.",
            "Analyse en temps réel intégrée à une messagerie.",
            "Authentification des analystes et rapports PDF."]),

    ("h1", "Organisation du travail et livrables obligatoires"),
    ("p", "Pour que le projet soit considéré comme complet, les étudiants doivent fournir les "
          "éléments suivants :"),
    ("ul", ["Un rapport technique structuré suivant les six parties du cahier des charges.",
            "Une présentation des menaces de phishing étudiées et de leur fonctionnement.",
            "Un code fonctionnel de l'application PhishGuard AI (analyse d'emails et d'URL).",
            "Un pipeline de préparation des données et un script d'entraînement.",
            "Les datasets utilisés (SpamAssassin, Nazario), documentés avec leurs sources.",
            "Des notebooks Jupyter pour l'exploration des données et l'entraînement des modèles.",
            "Une étude comparative des algorithmes avec des résultats mesurables.",
            "Le modèle entraîné intégré dans l'application, avec ses métadonnées.",
            "Une démonstration pratique de l'application (analyse, historique, tableau de bord).",
            "Des tableaux, graphiques et captures d'écran justifiant les résultats."]),

    ("h1", "Consignes générales aux étudiants"),
    ("ul", ["Le travail peut être réalisé individuellement, en binôme ou en trinôme (maximum trois "
            "étudiants).",
            "La réalisation technique est obligatoire : un projet uniquement théorique ne sera pas "
            "suffisant.",
            "L'application et les modèles doivent être accompagnés de codes fonctionnels.",
            "Aucun email réel ne doit être envoyé et aucun lien suspect ne doit être ouvert : les "
            "démonstrations utilisent des exemples synthétiques.",
            "Les étudiants doivent justifier leurs choix techniques et scientifiques.",
            "Les résultats expérimentaux doivent être présentés et analysés.",
            "Le rapport ne doit pas dépasser 30 pages.",
            "La présentation orale doit mettre en évidence les démonstrations pratiques et les "
            "résultats obtenus."]),

    ("h1", "Synthèse : démarche globale du projet"),
    ("ol", ["Comprendre les techniques de phishing et leurs indicateurs.",
            "Étudier les outils et l'architecture de l'application.",
            "Constituer le dataset à partir des corpus SpamAssassin et Nazario.",
            "Préparer les données et développer les modèles de Machine Learning.",
            "Comparer les algorithmes et sélectionner le meilleur modèle.",
            "Intégrer le modèle dans l'application web PhishGuard AI.",
            "Analyser les emails et les URL, calculer le score de risque et expliquer le verdict.",
            "Évaluer les performances et présenter une démonstration complète."]),
    ("key", ("Point essentiel : ",
             "le projet ne consiste pas uniquement à appliquer des algorithmes de Machine Learning "
             "sur un dataset. Les étudiants doivent réaliser toute la chaîne de traitement : "
             "comprendre les menaces, préparer les données, développer et comparer les modèles, "
             "sélectionner le meilleur modèle, puis l'intégrer dans l'application PhishGuard AI "
             "pour analyser les emails et les URL et estimer leur risque de phishing de façon "
             "explicable.")),
]  # fmt: skip


# =============================================================================
# XML patterns copied from the model
# =============================================================================
def t(text: str) -> str:
    return f'<w:t xml:space="preserve">{escape(text)}</w:t>'


def cover() -> str:
    lines = "<w:br/>".join(t(line) for line in COVER_LINES)
    return (
        '<w:p><w:pPr><w:spacing w:before="1800"/><w:jc w:val="center"/></w:pPr><w:r><w:rPr>'
        '<w:rFonts w:ascii="Arial" w:hAnsi="Arial"/><w:b/><w:color w:val="17365D"/>'
        '<w:sz w:val="50"/></w:rPr><w:t>CAHIER DES CHARGES</w:t></w:r></w:p>'
        '<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val="1F4E79"/>'
        f'<w:sz w:val="34"/></w:rPr>{lines}</w:r></w:p>'
        '<w:p><w:pPr><w:spacing w:before="500"/><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:i/>'
        f'<w:sz w:val="24"/></w:rPr>{t(COVER_NOTE)}</w:r></w:p>'
        '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'
    )


def styled(style: str, text: str, num_id: str | None = None) -> str:
    num = f'<w:numPr><w:ilvl w:val="0"/><w:numId w:val="{num_id}"/></w:numPr>' if num_id else ""
    return f'<w:p><w:pPr><w:pStyle w:val="{style}"/>{num}</w:pPr><w:r>{t(text)}</w:r></w:p>'


def plain(text: str) -> str:
    return f"<w:p><w:r>{t(text)}</w:r></w:p>"


TABLE_OPEN = (
    '<w:tbl><w:tblPr><w:tblStyle w:val="LightShading-Accent1"/><w:tblW w:type="auto" w:w="0"/>'
    '<w:jc w:val="center"/><w:tblLook w:firstColumn="1" w:firstRow="1" w:lastColumn="0" '
    'w:lastRow="0" w:noHBand="0" w:noVBand="1" w:val="04A0"/></w:tblPr><w:tblGrid>'
    '<w:gridCol w:w="4873"/><w:gridCol w:w="4873"/></w:tblGrid>'
)


def metrics_table(rows: list[list[str]]) -> str:
    def cell(text: str) -> str:
        return (
            '<w:tc><w:tcPr><w:tcW w:type="dxa" w:w="4873"/><w:vAlign w:val="center"/></w:tcPr>'
            '<w:p><w:r><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial"/><w:sz w:val="19"/>'
            f"</w:rPr>{t(text)}</w:r></w:p></w:tc>"
        )

    body = "".join("<w:tr>" + "".join(cell(c) for c in row) + "</w:tr>" for row in rows)
    return TABLE_OPEN + body + "</w:tbl>"


def boxes_table(spec) -> str:
    left_title, left_items, right_title, right_items = spec

    def cell(content: str) -> str:
        return (
            '<w:tc><w:tcPr><w:tcW w:type="dxa" w:w="4873"/></w:tcPr>'
            f"<w:p><w:r>{content}</w:r></w:p></w:tc>"
        )

    def items(lst: list[str]) -> str:
        return "<w:br/>".join(t(f"• {x}") for x in lst)

    return (
        TABLE_OPEN
        + "<w:tr>" + cell(t(left_title)) + cell(t(right_title)) + "</w:tr>"
        + "<w:tr>" + cell(items(left_items)) + cell(items(right_items)) + "</w:tr>"
        + "</w:tbl>"
    )  # fmt: skip


def key_paragraph(spec) -> str:
    lead, rest = spec
    return (
        '<w:p><w:pPr><w:spacing w:before="240"/></w:pPr><w:r><w:rPr><w:b/></w:rPr>'
        f"{t(lead)}</w:r><w:r>{t(rest)}</w:r></w:p>"
    )


def build_body() -> tuple[str, list[str]]:
    """Return the body XML and the extra numIds needed to restart numbered lists."""
    parts = [cover()]
    extra_nums: list[str] = []
    numbered_lists = 0
    for kind, value in CONTENT:
        if kind == "h1":
            parts.append(styled("Heading1", value))
        elif kind == "h2":
            parts.append(styled("Heading2", value))
        elif kind == "h3":
            parts.append(styled("Heading3", value))
        elif kind == "p":
            parts.append(plain(value))
        elif kind == "ul":
            parts += [styled("ListBullet", item) for item in value]
        elif kind == "ol":
            numbered_lists += 1
            num_id = None
            if numbered_lists > 1:  # model bug: the 2nd list continued at 9; restart at 1
                num_id = str(100 + numbered_lists)
                extra_nums.append(num_id)
            parts += [styled("ListNumber", item, num_id) for item in value]
        elif kind == "table":
            parts.append(metrics_table(value))
        elif kind == "boxes":
            parts.append(boxes_table(value))
        elif kind == "key":
            parts.append(key_paragraph(value))
        else:
            raise ValueError(kind)
    return "".join(parts), extra_nums


# =============================================================================
# Package assembly
# =============================================================================
def build_docx() -> None:
    src = zipfile.ZipFile(MODEL)
    body, extra_nums = build_body()

    doc = src.read("word/document.xml").decode("utf-8")
    sect = re.search(r"<w:sectPr.*?</w:sectPr>", doc, re.S).group(0)
    start = doc.index("<w:body>") + len("<w:body>")
    end = doc.index("</w:body>")
    new_doc = doc[:start] + body + sect + doc[end:]

    numbering = src.read("word/numbering.xml").decode("utf-8")
    nums = "".join(
        f'<w:num w:numId="{n}"><w:abstractNumId w:val="{NUMBER_ABSTRACT_ID}"/>'
        '<w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride></w:num>'
        for n in extra_nums
    )
    numbering = numbering.replace("</w:numbering>", nums + "</w:numbering>")

    header = src.read("word/header1.xml").decode("utf-8")
    header = re.sub(r"<w:t>[^<]*</w:t>", f"<w:t>{HEADER_TEXT}</w:t>", header, count=1)

    core = src.read("docProps/core.xml").decode("utf-8")
    core = core.replace("<dc:title/>", "<dc:title>Cahier des charges — PhishGuard AI</dc:title>")
    core = core.replace(
        "<dc:creator>python-docx</dc:creator>", "<dc:creator>PhishGuard AI</dc:creator>"
    )
    core = core.replace(
        "<dc:description>generated by python-docx</dc:description>", "<dc:description/>"
    )

    rels = src.read("_rels/.rels").decode("utf-8")
    rels = re.sub(r'<Relationship [^>]*Target="docProps/thumbnail\.jpeg"/>', "", rels)

    replaced = {
        "word/document.xml": new_doc,
        "word/numbering.xml": numbering,
        "word/header1.xml": header,
        "docProps/core.xml": core,
        "_rels/.rels": rels,
    }
    with zipfile.ZipFile(OUT_DOCX, "w", zipfile.ZIP_DEFLATED) as out:
        for item in src.infolist():
            if item.filename.endswith("/") or item.filename == "docProps/thumbnail.jpeg":
                continue  # no folder entries; drop the model's preview image
            data = replaced.get(item.filename)
            out.writestr(item.filename, data.encode("utf-8") if data else src.read(item.filename))
    print("docx", OUT_DOCX.relative_to(ROOT))


def export_pdf() -> None:
    """Export the .docx to PDF with Microsoft Word (read-only open)."""
    ps = (
        "$w = New-Object -ComObject Word.Application; $w.Visible = $false; $w.DisplayAlerts = 0; "
        f"try {{ $d = $w.Documents.Open('{OUT_DOCX}', $false, $true); "
        f"$d.ExportAsFixedFormat('{OUT_PDF}', 17); $d.Close(0) }} finally {{ $w.Quit() }}"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True)  # noqa: S607
    print("pdf ", OUT_PDF.relative_to(ROOT))


if __name__ == "__main__":
    build_docx()
    export_pdf()
