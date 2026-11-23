"""Build the French report and demo guide as PDF and Word (.docx).

    .\\.venv\\Scripts\\python.exe docs\\build\\build_docs.py

1. Renders the architecture diagrams to PNG (docs/screenshots/diagram_*.png).
2. For each document of doc_content.py:
   - HTML -> PDF with Microsoft Edge (Playwright), A4, numbered footer;
   - JSON -> .docx with docx-js (docs/build/build_docx.js).
Outputs: docs/Rapport_PhishGuard_AI.{pdf,docx}, docs/Guide_Demonstration_PhishGuard_AI.{pdf,docx}
"""

from __future__ import annotations

import html
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from doc_content import DOCUMENTS  # noqa: E402
from PIL import Image  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

BUILD = Path(__file__).resolve().parent
ROOT = BUILD.parents[1]
DOCS = ROOT / "docs"
SHOTS = DOCS / "screenshots"

ACCENT = "#0e7490"
NAVY = "#0b1f3a"

# --- Diagrams --------------------------------------------------------------------
DIAGRAM_CSS = """
body{margin:0;background:#fff;font-family:"Segoe UI",Arial,sans-serif;color:#0f172a}
.wrap{padding:28px;display:inline-block}
.band{border:2px solid #cbd5e1;border-radius:14px;padding:14px 18px;margin:0 0 14px 0}
.band h3{margin:0 0 10px 0;font-size:17px;color:#0b1f3a}
.band small{color:#475569;font-weight:400}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{background:#f1f5f9;border:1px solid #cbd5e1;border-radius:8px;padding:6px 11px;font-size:14px}
.ui{border-color:#22d3ee;background:#ecfeff}.svc{border-color:#3b82f6;background:#eff6ff}
.ml{border-color:#a855f7;background:#faf5ff}.db{border-color:#f59e0b;background:#fffbeb}
.row{display:flex;gap:14px}.row .band{flex:1}
.arrow{text-align:center;color:#64748b;font-size:20px;margin:-6px 0 6px 0}
.flow{display:flex;align-items:stretch;gap:0}
.step{width:150px;border:2px solid #3b82f6;background:#eff6ff;border-radius:12px;padding:12px;
 font-size:13.5px;text-align:center;display:flex;flex-direction:column;justify-content:center}
.step b{display:block;font-size:15px;margin-bottom:4px;color:#0b1f3a}
.step.ai{border-color:#a855f7;background:#faf5ff}.step.rule{border-color:#0ea5e9;background:#f0f9ff}
.step.out{border-color:#16a34a;background:#f0fdf4}.step.in{border-color:#64748b;background:#f8fafc}
.ar{display:flex;align-items:center;padding:0 6px;color:#64748b;font-size:22px}
.stack{display:flex;flex-direction:column;gap:10px}
"""

ARCHITECTURE = """
<div class="wrap" style="width:980px">
 <div class="band ui"><h3>Interface Streamlit <small>— pages/, components/</small></h3>
  <div class="chips"><span class="chip">Dashboard</span><span class="chip">History</span>
  <span class="chip">Email analysis</span><span class="chip">URL analysis</span>
  <span class="chip">Model evaluation</span><span class="chip">About</span></div></div>
 <div class="arrow">▼ appelle uniquement les services</div>
 <div class="band svc"><h3>Services métier <small>— services/</small></h3>
  <div class="chips"><span class="chip">validation</span><span class="chip">email_analyzer</span>
  <span class="chip">url_analyzer (hors ligne)</span><span class="chip">risk_engine</span>
  <span class="chip">analysis (façade)</span><span class="chip">history</span>
  <span class="chip">reports (CSV)</span><span class="chip">evaluation</span></div></div>
 <div class="arrow">▼</div>
 <div class="row">
  <div class="band ml"><h3>Intelligence artificielle <small>— ml/</small></h3>
   <div class="chips"><span class="chip">preprocess</span><span class="chip">dataset</span>
   <span class="chip">train</span><span class="chip">predict (SHA-256)</span></div></div>
  <div class="band db"><h3>Persistance <small>— database/</small></h3>
   <div class="chips"><span class="chip">repository</span><span class="chip">SQLite</span>
   <span class="chip">requêtes paramétrées</span></div></div>
 </div>
 <div class="band"><h3>Configuration et outils <small>— config/, scripts/, tests/</small></h3>
  <div class="chips"><span class="chip">settings (PHISHGUARD_*)</span><span class="chip">prepare_data</span>
  <span class="chip">evaluate_engine</span><span class="chip">seed_demo</span>
  <span class="chip">210 tests pytest</span></div></div>
</div>"""

FLOW = """
<div class="wrap"><div class="flow">
 <div class="step in"><b>Saisie</b>Email collé, fichier .txt ou URL</div><div class="ar">➜</div>
 <div class="step in"><b>Validation</b>Taille, binaire, schéma d'URL</div><div class="ar">➜</div>
 <div class="step"><b>Extraction</b>Objet, corps, liens, expéditeur, noms de pièces jointes</div>
 <div class="ar">➜</div>
 <div class="stack"><div class="step ai"><b>IA</b>TF-IDF + SVM<br>probabilité + termes</div>
  <div class="step rule"><b>Règles</b>Contenu, liens, expéditeur, pièces jointes</div></div>
 <div class="ar">➜</div>
 <div class="step"><b>Score</b>Combinaison IA + règles<br>verdict prudent</div><div class="ar">➜</div>
 <div class="step out"><b>Résultat</b>Indicateurs, conseils, export CSV, historique</div>
</div></div>"""


def render_diagrams(browser) -> None:
    page = browser.new_page(device_scale_factor=2)
    for name, body in (("diagram_architecture", ARCHITECTURE), ("diagram_flow", FLOW)):
        page.set_content(
            f"<html><head><style>{DIAGRAM_CSS}</style></head><body>{body}</body></html>"
        )
        page.locator(".wrap").screenshot(path=str(SHOTS / f"{name}.png"))
        print("diagram", name)
    page.close()


# --- Inline markup ----------------------------------------------------------------
def inline_html(text: str) -> str:
    out = html.escape(text)
    out = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    out = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<i>\1</i>", out)
    return out


PDF_CSS = f"""
@page {{ size: A4; margin: 18mm 17mm 20mm 17mm; }}
body {{ font-family: "Segoe UI", Calibri, Arial, sans-serif; font-size: 10.6pt; color: #1e293b;
  line-height: 1.5; }}
h1 {{ font-size: 18pt; color: {NAVY}; margin: 22pt 0 8pt; padding-bottom: 4pt;
  border-bottom: 2px solid {ACCENT}; page-break-after: avoid; }}
h2 {{ font-size: 13.5pt; color: {ACCENT}; margin: 16pt 0 6pt; page-break-after: avoid; }}
h3 {{ font-size: 11.5pt; color: {NAVY}; margin: 12pt 0 4pt; page-break-after: avoid; }}
p {{ margin: 0 0 7pt; text-align: justify; }}
/* keep an introductory paragraph on the same page as the code/figure it introduces */
p:has(+ pre), p:has(+ figure), p:has(+ table), p:has(+ ol), p:has(+ ul) {{ break-after: avoid; }}
ul, ol {{ margin: 0 0 8pt 18pt; padding: 0; }} li {{ margin: 0 0 3pt; }}
code {{ font-family: Consolas, "Cascadia Mono", monospace; font-size: 9.3pt; background: #f1f5f9;
  padding: 0 3px; border-radius: 3px; }}
pre {{ font-family: Consolas, monospace; font-size: 9pt; background: #0f172a; color: #e2e8f0;
  padding: 9pt 11pt; border-radius: 6px; white-space: pre-wrap; page-break-inside: avoid; }}
table {{ width: 100%; border-collapse: collapse; margin: 6pt 0 10pt; font-size: 9.4pt;
  page-break-inside: avoid; }}
th {{ background: {NAVY}; color: #fff; text-align: left; padding: 5pt 6pt; }}
td {{ border-bottom: 1px solid #e2e8f0; padding: 4.5pt 6pt; vertical-align: top; }}
tr:nth-child(even) td {{ background: #f8fafc; }}
figure {{ margin: 8pt 0 12pt; text-align: center; page-break-inside: avoid; }}
figure img {{ max-width: 100%; border: 1px solid #cbd5e1; border-radius: 4px; }}
figcaption {{ font-size: 8.8pt; color: #475569; font-style: italic; margin-top: 4pt; }}
.note {{ border-left: 4px solid {ACCENT}; background: #ecfeff; padding: 7pt 10pt; margin: 6pt 0 10pt;
  page-break-inside: avoid; }} .note.warn {{ border-color: #d97706; background: #fffbeb; }}
.break {{ page-break-after: always; }}
.toc h2 {{ color: {NAVY}; }} .toc ol {{ list-style: none; margin-left: 0; }}
.toc li {{ padding: 3pt 0; border-bottom: 1px dotted #cbd5e1; }}
.cover {{ height: 245mm; display: flex; flex-direction: column; justify-content: space-between;
  page-break-after: always; }}
.cover .band {{ background: {NAVY}; color: #fff; margin: -18mm -17mm 0; padding: 30mm 22mm 22mm; }}
.cover .kind {{ color: #67e8f9; letter-spacing: .14em; text-transform: uppercase; font-size: 10pt;
  font-weight: 600; }}
.cover .title {{ font-size: 36pt; font-weight: 800; margin-top: 8pt; }}
.cover .title span {{ color: #22d3ee; }}
.cover .sub {{ font-size: 15pt; color: #cbd5e1; margin-top: 6pt; }}
.cover .ctx {{ font-size: 10.5pt; color: #94a3b8; margin-top: 18pt; }}
.cover table td {{ border: none; padding: 4pt 0; font-size: 11pt; background: none !important; }}
.cover table td:first-child {{ color: #64748b; width: 42%; }}
"""


def block_html(b: dict, toc: list[str], img_sizes: dict) -> str:
    t = b["t"]
    if t in ("h1", "h2", "h3"):
        return f"<{t}>{inline_html(b['text'])}</{t}>"
    if t == "p":
        return f"<p>{inline_html(b['text'])}</p>"
    if t in ("ul", "ol"):
        items = "".join(f"<li>{inline_html(i)}</li>" for i in b["items"])
        return f"<{t}>{items}</{t}>"
    if t == "code":
        return f"<pre>{html.escape(b['text'])}</pre>"
    if t == "note":
        return f'<div class="note {b.get("kind", "info")}">{inline_html(b["text"])}</div>'
    if t == "pagebreak":
        return '<div class="break"></div>'
    if t == "toc":
        items = "".join(f"<li>{inline_html(h)}</li>" for h in toc)
        return f'<div class="toc"><h2>Sommaire</h2><ol>{items}</ol></div>'
    if t == "table":
        widths = b.get("widths")
        cols = "".join(f'<col style="width:{w * 100:.1f}%">' for w in widths) if widths else ""
        head = "".join(f"<th>{inline_html(h)}</th>" for h in b["head"])
        rows = "".join(
            "<tr>" + "".join(f"<td>{inline_html(str(c))}</td>" for c in r) + "</tr>"
            for r in b["rows"]
        )
        return f"<table><colgroup>{cols}</colgroup><tr>{head}</tr>{rows}</table>"
    if t == "img":
        src = (SHOTS / b["src"]).as_uri()
        return (
            f'<figure><img src="{src}" style="width:{b.get("width", 1) * 100:.0f}%">'
            f"<figcaption>{inline_html(b['caption'])}</figcaption></figure>"
        )
    raise ValueError(f"unknown block {t}")


def cover_html(doc: dict) -> str:
    fields = "".join(
        f"<tr><td>{html.escape(a)}</td><td><b>{html.escape(v)}</b></td></tr>"
        for a, v in doc["fields"]
    )
    title = html.escape(doc["title"]).replace("Guard", "<span>Guard</span>")
    return (
        '<div class="cover"><div class="band">'
        f'<div class="kind">{html.escape(doc["kind"])}</div>'
        f'<div class="title">🛡️ {title}</div>'
        f'<div class="sub">{html.escape(doc["subtitle"])}</div>'
        f'<div class="ctx">{html.escape(doc["context"])}</div></div>'
        f"<table>{fields}</table></div>"
    )


def build_pdf(browser, doc: dict, out: Path) -> None:
    toc = [b["text"] for b in doc["blocks"] if b["t"] == "h1" and b["text"] != "Résumé"]
    body = "".join(block_html(b, toc, {}) for b in doc["blocks"])
    page_html = (
        f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><style>{PDF_CSS}</style>'
        f"</head><body>{cover_html(doc)}{body}</body></html>"
    )
    tmp = BUILD / f"_{doc['file']}.html"
    tmp.write_text(page_html, encoding="utf-8")
    page = browser.new_page()
    page.goto(tmp.as_uri(), wait_until="load")
    footer = (
        '<div style="width:100%;font-size:8px;color:#64748b;padding:0 17mm;'
        'display:flex;justify-content:space-between;font-family:Segoe UI,Arial">'
        f"<span>PhishGuard AI — {html.escape(doc['kind'])}</span>"
        '<span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>'
    )
    page.pdf(
        path=str(out),
        format="A4",
        print_background=True,
        display_header_footer=True,
        header_template="<div></div>",
        footer_template=footer,
        margin={"top": "18mm", "bottom": "20mm", "left": "17mm", "right": "17mm"},
    )
    page.close()
    tmp.unlink()
    print("pdf ", out.relative_to(ROOT))


def build_docx(doc: dict, out: Path) -> None:
    blocks = []
    toc = [b["text"] for b in doc["blocks"] if b["t"] == "h1" and b["text"] != "Résumé"]
    for b in doc["blocks"]:
        b = dict(b)
        if b["t"] == "img":
            path = SHOTS / b["src"]
            with Image.open(path) as im:
                b["px"] = im.size
            b["path"] = str(path)
        if b["t"] == "toc":
            b["items"] = toc
        blocks.append(b)
    spec = {**{k: doc[k] for k in ("kind", "title", "subtitle", "context", "fields")},
            "blocks": blocks, "out": str(out)}  # fmt: skip
    spec_path = BUILD / f"_{doc['file']}.json"
    spec_path.write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
    subprocess.run(["node", str(BUILD / "build_docx.js"), str(spec_path)], check=True, cwd=BUILD)  # noqa: S607
    spec_path.unlink()
    print("docx", out.relative_to(ROOT))


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        render_diagrams(browser)
        for doc in DOCUMENTS:
            build_pdf(browser, doc, DOCS / f"{doc['file']}.pdf")
            build_docx(doc, DOCS / f"{doc['file']}.docx")
        browser.close()


if __name__ == "__main__":
    main()
