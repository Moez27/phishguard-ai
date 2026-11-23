# CAHIER DES CHARGES

## PhishGuard AI — Plateforme intelligente de détection et d’analyse du phishing

_Version 1.0 | Projet ingénieur en cybersécurité | Durée cible : 5 semaines_

| Champ | Valeur |
|---|---|
| Nom du projet | PhishGuard AI |
| Domaine | Cybersécurité défensive, IA et développement web |
| Environnement | 100 % logiciel — sans machines virtuelles |


## 1. Présentation du projet

### 1.1 Contexte

Le phishing est une menace qui s’appuie sur des emails, des liens et des contenus trompeurs afin d’inciter les utilisateurs à divulguer des informations ou à effectuer une action dangereuse. Le projet consiste à développer une application web qui aide à analyser des emails et des URL et à estimer leur niveau de risque.

### 1.2 Objectif général

Concevoir et réaliser PhishGuard AI, une plateforme web de démonstration intégrant l’analyse de messages et d’URL, un modèle de classification automatique, un tableau de bord et un historique des analyses.

### 1.3 Référence du sujet

Le projet correspond au Projet 7 du document « Cybersecurity Projects.pdf » : détection des emails de phishing par IA. Le document propose Python, Scikit-learn, BeautifulSoup, Streamlit et Jupyter ; les modèles Naive Bayes, SVM ou BERT ; et les datasets SpamAssassin Public Corpus et Nazario Phishing Corpus.

## 2. Périmètre et contraintes

### 2.1 Inclus dans le périmètre

• Application web locale ou déployable sur une plateforme standard.
• Analyse de texte d’email fourni par l’utilisateur.
• Analyse de l’URL fournie par l’utilisateur.
• Classification : légitime, phishing ou suspect.
• Score de risque, facteurs explicatifs et recommandations prudentes.
• Dashboard, historique, filtres et export de rapports.
• Entraînement et évaluation d’un modèle ML à partir de données autorisées.

### 2.2 Hors périmètre

• Aucun déploiement sur des machines virtuelles n’est requis.
• Aucun matériel spécialisé.
• Aucun envoi réel d’emails ni campagne de phishing.
• Aucune visite automatique de liens potentiellement dangereux par défaut.
• Aucune garantie qu’un email ou une URL est parfaitement sûre.

### 2.3 Contraintes

• Durée : 5 semaines.
• Réalisation principalement en Python.
• Outils et datasets logiciels/publics.
• Interface claire, démontrable et documentée.
• Les données d’analyse doivent être traitées avec prudence et ne pas être publiées sans consentement.

## 3. Utilisateurs et rôles

### 3.1 Utilisateur analyste

Peut soumettre un email ou une URL, consulter le résultat, examiner les indicateurs détectés et parcourir l’historique disponible.

### 3.2 Administrateur / responsable de démonstration

Peut consulter les statistiques globales, gérer les données de démonstration et lancer ou remplacer le modèle entraîné selon les fonctionnalités retenues.

### 3.3 Mode MVP

Pour tenir les cinq semaines, l’application peut fonctionner sans système complexe de comptes. L’authentification est une fonctionnalité optionnelle, à ajouter seulement si le temps le permet.

## 4. Fonctionnalités attendues

### F01 — Page d’accueil et dashboard

Afficher le nombre d’analyses, la répartition des verdicts, les tendances d’activité et les dernières analyses. Les indicateurs doivent provenir des données réellement enregistrées.

### F02 — Analyse d’email

Permettre de coller le contenu d’un email ou de charger un fichier texte simple. Extraire le texte, l’objet si disponible, les liens et des caractéristiques utiles. Refuser ou signaler les formats non pris en charge.

### F03 — Analyse d’URL

Accepter une URL saisie manuellement et calculer des caractéristiques lexicales et structurelles : longueur, présence d’une adresse IP, caractères inhabituels, nombre de sous-domaines, utilisation de HTTPS, mots-clés suspects et autres signaux explicables. Ne pas affirmer qu’une vérification de réputation externe a été réalisée si aucun service externe n’est configuré.

### F04 — Classification IA

Utiliser un modèle supervisé entraîné sur des données adaptées. Produire une classe prédite et, si le modèle le permet, une probabilité ou un score calibré. Afficher les limites du score et éviter de le présenter comme une certitude.

### F05 — Explication du résultat

Présenter des indicateurs observables ayant contribué au verdict, par exemple présence de liens, langage d’urgence, demande d’identifiants ou caractéristiques anormales de l’URL. Les explications doivent être fondées sur les règles/features réellement implémentées.

### F06 — Historique

Enregistrer la date, le type d’analyse, le verdict, le score et un identifiant. Prévoir la recherche, le filtrage par verdict et la suppression des enregistrements. Par défaut, éviter de conserver le corps complet des emails.

### F07 — Rapports

Permettre l’export d’un résultat ou de statistiques au format CSV. Un PDF est facultatif si le temps restant le permet.

### F08 — Évaluation du modèle

Présenter les métriques d’évaluation : précision, rappel, F1-score, matrice de confusion et, lorsque pertinent, ROC-AUC. Indiquer le dataset, la méthode de séparation train/test et les limites connues.

### F09 — Gestion des erreurs

Afficher des messages compréhensibles pour les entrées vides, URL invalides, fichiers non pris en charge, données manquantes et erreurs du modèle.

## 5. Exigences non fonctionnelles

### Sécurité et confidentialité

Ne pas exécuter les pièces jointes. Ne pas ouvrir automatiquement les liens soumis. Éviter les logs contenant des données personnelles ou le contenu complet des emails. Valider et limiter la taille des entrées. Protéger les secrets dans des variables d’environnement.

### Performance

Sur une machine de développement standard, une analyse simple doit généralement se terminer en quelques secondes, hors téléchargement ou entraînement du modèle. L’entraînement ne doit pas bloquer l’interface utilisateur.

### Ergonomie

Interface responsive et lisible, navigation simple, distinction visuelle des verdicts sans se reposer uniquement sur la couleur, graphiques compréhensibles et textes en français ou anglais cohérents

### Maintenabilité

Code organisé en modules, fonctions réutilisables, dépendances déclarées, configuration centralisée, README et tests automatisés essentiels

### Reproductibilité

Fournir les étapes d’installation, de préparation des données, d’entraînement et de lancement. Fixer les versions ou plages de versions des dépendances

## 6. Proposition de technologies

### Interface

Streamlit (conforme au sujet source et rapide à développer)

### Langage et traitement

Python, pandas, NumPy, BeautifulSoup si nécessaire pour parser des contenus HTML fournis

### Machine Learning

Scikit-learn : baseline Naive Bayes ou SVM avec TF-IDF. BERT peut être envisagé en extension si les ressources et le temps le permettent

### Persistance

SQLite pour l’historique et les statistiques locales

### Visualisation

Plotly ou graphiques Streamlit

### Tests et qualité

pytest, ruff ou équivalent, validation manuelle documentée

### Environnement

Environnement Python virtuel de projet (venv) recommandé ; cela ne nécessite pas de machine virtuelle système

## 7. Données et stratégie IA

### Sources de données

SpamAssassin Public Corpus et Nazario Phishing Corpus, cités dans le document de projet. Vérifier les conditions d’utilisation, la disponibilité, la qualité et les étiquettes avant intégration.

### Prétraitement

Nettoyage du texte, normalisation raisonnable, extraction des URLs et suppression des doublons. Prévenir les fuites de données entre entraînement et test

### Baseline recommandée

Pipeline TF-IDF + Naive Bayes ou SVM. Comparer au moins deux approches si le calendrier le permet

### Évaluation

Séparer les données en train/test de manière reproductible ; privilégier les métriques adaptées aux classes déséquilibrées, en particulier précision, rappel et F1-score pour la classe phishing

### Limites

Le modèle est un outil d’aide à la décision. Les résultats dépendent des datasets, de leur fraîcheur et de la représentativité des emails observés. Les données d’entraînement ne doivent pas être présentées comme une preuve de détection en temps réel dans le monde réel

## 8. Architecture fonctionnelle cible

### Flux principal

Utilisateur → interface Streamlit → validation de l’entrée → extraction des caractéristiques → modèle ML et règles explicables → résultat et recommandations → stockage minimal de l’historique → dashboard/exports

### Organisation de code indicative

app.py ; pages/ ; components/ ; services/email_analyzer.py ; services/url_analyzer.py ; ml/preprocess.py ; ml/train.py ; ml/predict.py ; database/ ; tests/ ; data/README.md

### Séparation des responsabilités

L’interface ne doit pas contenir toute la logique métier. Les fonctions d’analyse, de prédiction, de persistance et de visualisation doivent être séparées et testables

## 9. Livrables

### L1

Code source complet et organisé dans un dépôt Git

### L2

Application web fonctionnelle et démontrable

### L3

Pipeline de préparation des données et script d’entraînement

### L4

Modèle entraîné et métadonnées/version du modèle

### L5

Rapport d’évaluation avec métriques et limites

### L6

README : installation, configuration, lancement, entraînement et utilisation

### L7

Jeu de tests et résultats des tests

### L8

Présentation et démonstration finale

## 10. Planification sur 5 semaines

### Semaine 1 — Cadrage et fondations

Valider les fonctionnalités MVP, organiser le dépôt, examiner les datasets, concevoir l’interface et le schéma de données. Livrable : structure du projet, backlog et prototype de pages

### Semaine 2 — Analyse et baseline ML

Construire le prétraitement email/URL, préparer les données, entraîner une baseline et mesurer les premières performances. Livrable : pipeline reproductible et prédiction de base

### Semaine 3 — Application et intégration

Développer les pages d’analyse, intégrer le modèle, implémenter le stockage minimal et les explications. Livrable : parcours utilisateur de bout en bout

### Semaine 4 — Dashboard et validation

Ajouter statistiques, historique, filtres, export CSV, tests, gestion d’erreurs et améliorations UI. Livrable : version bêta testable

### Semaine 5 — Stabilisation et soutenance

Corriger les bugs, vérifier les métriques, rédiger le README et le rapport, préparer les scénarios de démonstration. Livrable : version finale et présentation

## 11. Critères d’acceptation

### CA1

L’application démarre en suivant uniquement les instructions du README, sans VM

### CA2

Un utilisateur peut soumettre un email et obtenir un verdict, un score ou niveau de risque et des indicateurs

### CA3

Un utilisateur peut soumettre une URL valide et obtenir une analyse sans que l’application ouvre automatiquement le site

### CA4

Le dashboard affiche des statistiques calculées depuis les analyses enregistrées

### CA5

L’historique peut être filtré et supprimé

### CA6

Le modèle est évalué sur un jeu de test séparé et les métriques sont documentées

### CA7

Les entrées invalides et erreurs sont gérées proprement

### CA8

Le projet contient des tests essentiels et une documentation d’installation complète

## 12. Risques et mesures de réduction

### Datasets difficiles à préparer

Commencer par un sous-ensemble propre et documenter la source ; ne pas attendre la préparation de données parfaite pour construire l’interface

### Déséquilibre des classes ou biais

Analyser la distribution, utiliser une séparation adaptée et rapporter les métriques par classe

### Scope trop ambitieux

Prioriser email + URL + baseline ML + dashboard + historique ; considérer BERT, authentification et PDF comme extensions

### Faux positifs/faux négatifs

Afficher une formulation prudente, expliquer les signaux et ne jamais déclarer un email absolument sûr

### Dépendances ou problèmes d’intégration

Créer tôt un environnement reproductible, intégrer par petits modules et utiliser des tests

## 13. Extensions facultatives

### E1

Modèle BERT ou autre modèle NLP avancé

### E2

Connexion à une API de réputation d’URL, uniquement avec clé et source clairement affichées

### E3

Authentification et profils d’analystes

### E4

Rapport PDF

### E5

Import de fichiers .eml avec parsing sécurisé

### E6

Comparaison de plusieurs modèles dans une page dédiée

## 14. Consignes de développement avec Claude Code

### Méthode

Utiliser Claude Code comme assistant de développement, mais conserver le contrôle du code, des dépendances, des résultats ML et des tests. Travailler par tâches courtes et vérifier chaque changement

### Prompt de démarrage

Tu es un ingénieur logiciel senior spécialisé en Python, Streamlit et cybersécurité défensive. Construis PhishGuard AI conformément au cahier des charges présent dans le dépôt. Le projet doit fonctionner sans VM et ne doit jamais ouvrir automatiquement les URLs soumises ni exécuter de pièces jointes. Commence par analyser le dépôt, proposer une architecture et un plan de tâches. Implémente ensuite le MVP par étapes : validation des entrées, analyse email/URL, pipeline TF-IDF + modèle baseline Scikit-learn, dashboard, historique SQLite, tests et README. Ne prétends pas qu’une fonctionnalité est terminée sans l’avoir testée. N’invente pas de résultats de métriques ; calcule-les sur un jeu de test séparé. Demande confirmation avant d’ajouter des services payants, des clés API ou des fonctionnalités hors périmètre.

### Règle de collaboration

Ne demander à Claude Code de générer tout le projet en une seule fois. Commencer par l’architecture, puis implémenter et tester un module à la fois. Faire des commits Git fréquents

---
Fin du cahier des charges — PhishGuard AI
