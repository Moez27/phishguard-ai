"""Record a captioned MP4 demonstration of PhishGuard AI (French captions).

A real, scripted run of the application (Edge, 1280x720) with on-screen captions
and a visible pointer. Frames are captured continuously with their real
timestamps (no extra download needed) and assembled into an H.264 MP4 with the
ffmpeg bundled in imageio-ffmpeg. The history starts empty: the dashboard fills
up with the analyses performed in the video.

Run from the project root:
    .\\.venv\\Scripts\\python.exe docs\\build\\record_demo.py
Output: docs/media/phishguard_demo.mp4
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import imageio_ffmpeg  # noqa: E402
from app_driver import MEDIA, ROOT, reset_demo_database, running_app  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

PORT = 8511
W, H = 1280, 720
OUTPUT = MEDIA / "phishguard_demo.mp4"

OVERLAY_JS = r"""
(() => {
  const setup = () => {
    if (!document.body || document.getElementById('pg-demo-cap')) return;
    const cap = document.createElement('div');
    cap.id = 'pg-demo-cap';
    Object.assign(cap.style, {
      position: 'fixed', left: '50%', bottom: '26px', transform: 'translateX(-50%)',
      maxWidth: '82%', background: 'rgba(6,11,24,0.94)', color: '#f8fafc',
      border: '1px solid #22d3ee', borderRadius: '10px', padding: '11px 22px',
      font: '600 19px/1.4 "Segoe UI", Arial, sans-serif', textAlign: 'center',
      zIndex: 2147483647, boxShadow: '0 8px 28px rgba(0,0,0,.55)', opacity: '0',
      transition: 'opacity .35s', pointerEvents: 'none'
    });
    document.body.appendChild(cap);
    const cur = document.createElement('div');
    cur.id = 'pg-demo-cursor';
    Object.assign(cur.style, {
      position: 'fixed', left: '-60px', top: '-60px', width: '24px', height: '24px',
      borderRadius: '50%', background: 'rgba(34,211,238,.30)', border: '2px solid #22d3ee',
      zIndex: 2147483647, pointerEvents: 'none', transform: 'translate(-50%,-50%)',
      transition: 'transform .12s'
    });
    document.body.appendChild(cur);
    document.addEventListener('mousemove', e => {
      cur.style.left = e.clientX + 'px'; cur.style.top = e.clientY + 'px';
    }, true);
    document.addEventListener('mousedown', () => {
      cur.style.transform = 'translate(-50%,-50%) scale(.65)'; }, true);
    document.addEventListener('mouseup', () => {
      cur.style.transform = 'translate(-50%,-50%) scale(1)'; }, true);
  };
  window.__pgCaption = (html) => {
    setup();
    const c = document.getElementById('pg-demo-cap');
    if (!html) { c.style.opacity = '0'; return; }
    c.innerHTML = html; c.style.opacity = '1';
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setup);
  else setup();
})();
"""

CARD_HTML = """<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(circle at 30% 20%,#13203a,#0b1120 60%);color:#e2e8f0;
font-family:"Segoe UI",Arial,sans-serif}}
.box{{text-align:center;max-width:900px}}
.logo{{font-size:64px;font-weight:800;letter-spacing:-1px}} .logo span{{color:#22d3ee}}
.sub{{font-size:26px;color:#94a3b8;margin-top:14px}}
.list{{margin-top:34px;font-size:20px;color:#cbd5e1;line-height:1.7}}
.tag{{display:inline-block;margin-top:30px;padding:6px 16px;border:1px solid #22d3ee;
border-radius:999px;color:#22d3ee;font-size:16px;letter-spacing:.08em}}
</style></head><body><div class="box">{body}</div></body></html>"""

INTRO = CARD_HTML.format(
    body='<div class="logo">🛡️ Phish<span>Guard</span> AI</div>'
    '<div class="sub">Détection du phishing dans les emails et les URL par IA</div>'
    "<div class=\"list\">Analyse d'emails · Analyse d'URL hors ligne · Modèle TF-IDF + SVM<br>"
    "Règles explicables · Tableau de bord · Historique · Évaluation du modèle</div>"
    '<div class="tag">DÉMONSTRATION</div>'
)
OUTRO = CARD_HTML.format(
    body='<div class="logo">🛡️ Phish<span>Guard</span> AI</div>'
    '<div class="sub">Un outil d\'aide à la décision — jamais une garantie.</div>'
    '<div class="list">Liens jamais ouverts · Pièces jointes jamais exécutées<br>'
    "Stockage minimal · Application locale (localhost)<br>"
    "Précision 0,990 · Rappel 0,987 · F1 0,988 (jeu de test de 1 506 emails)</div>"
    '<div class="tag">MERCI</div>'
)


class Recorder:
    """Drives the page and captures frames continuously (about 10-15 per second)."""

    def __init__(self, page, frames_dir: Path) -> None:
        self.page = page
        self.dir = frames_dir
        self.frames: list[tuple[float, Path]] = []
        self.mouse = (W / 2, H / 2)

    def snap(self) -> None:
        path = self.dir / f"{len(self.frames):06d}.jpg"
        self.page.screenshot(path=str(path), type="jpeg", quality=85)
        self.frames.append((time.perf_counter(), path))

    def pause(self, ms: int) -> None:
        end = time.perf_counter() + ms / 1000
        self.snap()
        while time.perf_counter() < end:
            self.snap()

    def idle(self, settle_ms: int = 700, timeout_s: float = 60) -> None:
        """Wait for Streamlit to finish its run, while recording."""
        deadline = time.perf_counter() + timeout_s
        quiet_since = None
        self.snap()
        while time.perf_counter() < deadline:
            busy = (
                self.page.locator('[data-testid="stStatusWidget"]').count() > 0
                or self.page.locator('[data-testid="stSkeleton"]').count() > 0
            )
            now = time.perf_counter()
            if busy:
                quiet_since = None
            elif quiet_since is None:
                quiet_since = now
            elif (now - quiet_since) * 1000 >= settle_ms:
                return
            self.snap()

    def goto(self, base_url: str, path: str) -> None:
        self.page.goto(f"{base_url}/{path}", wait_until="domcontentloaded")
        self.page.wait_for_selector(".pg-header h1", state="visible", timeout=90_000)
        self.idle()

    def caption(self, text: str | None, hold_ms: int = 0) -> None:
        self.page.evaluate("t => window.__pgCaption && window.__pgCaption(t)", text or "")
        if hold_ms:
            self.pause(hold_ms)

    def glide_click(self, locator, pause_ms: int = 350) -> None:
        """Move the pointer visibly to the element (recorded), then click it."""
        locator.scroll_into_view_if_needed()
        box = locator.bounding_box()
        if box:
            tx, ty = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
            x0, y0 = self.mouse
            steps = 14
            for i in range(1, steps + 1):
                k = i / steps
                k = k * k * (3 - 2 * k)  # ease in/out
                self.page.mouse.move(x0 + (tx - x0) * k, y0 + (ty - y0) * k)
                self.snap()
            self.mouse = (tx, ty)
            self.pause(pause_ms)
        locator.click()
        self.snap()

    def type_text(self, locator, text: str, every: int = 2) -> None:
        for i, ch in enumerate(text):
            locator.press_sequentially(ch)
            if i % every == 0:
                self.snap()
        self.snap()

    def scroll_main(self, dy: int, wait_ms: int = 1300) -> None:
        self.page.locator('[data-testid="stMain"]').evaluate(
            "(m, dy) => m.scrollBy({top: dy, behavior: 'smooth'})", dy
        )
        self.pause(wait_ms)

    def scroll_to(self, selector: str, wait_ms: int = 1300) -> None:
        self.page.locator(selector).first.evaluate(
            "el => el.scrollIntoView({behavior: 'smooth', block: 'start'})"
        )
        self.pause(wait_ms)

    def scroll_top(self) -> None:
        self.page.locator('[data-testid="stMain"]').evaluate(
            "m => m.scrollTo({top: 0, behavior: 'smooth'})"
        )
        self.pause(700)

    def load_example(self, prefix: str) -> None:
        combo = self.page.get_by_label("Synthetic examples", exact=False).first
        if not combo.is_visible():  # expander closed (clicking it again would close it)
            self.glide_click(self.page.get_by_text("Try a built-in example").first, 250)
            self.pause(400)
        self.glide_click(combo, 250)
        combo.fill(prefix)
        self.pause(500)
        self.page.keyboard.press("Enter")
        self.idle()

    def analyse_email_example(self, prefix: str, intro: str, details) -> None:
        self.caption(intro, 2600)
        self.load_example(prefix)
        self.pause(700)
        self.glide_click(self.page.get_by_role("button", name="Analyse email"))
        self.idle()
        self.scroll_to(".pg-verdict")
        for text, ms in details:
            self.caption(text, ms)
            self.scroll_main(330, 1100)


def record(frames_dir: Path) -> list[tuple[float, Path]]:
    reset_demo_database()
    with running_app(PORT) as url, sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(
            viewport={"width": W, "height": H}, color_scheme="dark", locale="fr-FR"
        )
        ctx.add_init_script(OVERLAY_JS)
        page = ctx.new_page()
        r = Recorder(page, frames_dir)

        # --- Intro card
        page.set_content(INTRO)
        r.pause(4500)

        # --- First launch
        r.goto(url, "")
        r.caption("Au premier lancement, l'historique est vide : le tableau de bord "
                  "le signale au lieu d'afficher de faux chiffres.", 4200)  # fmt: skip
        r.caption("Analysons d'abord des emails.", 1500)
        r.glide_click(page.get_by_role("link", name="Email analysis"))
        r.idle()

        # --- Email 1: credential phishing
        r.analyse_email_example(
            "Credential",
            "Exemple 1 : un email de phishing classique (domaines fictifs, sans danger).",
            [
                ("Verdict : <b>✖ Probablement du phishing — 86/100</b>. "
                 "Le score combine l'IA et des règles explicables.", 4200),
                ("Chaque indicateur est justifié : lien suspect, demande d'identifiants, "
                 "urgence, menace de suspension…", 4200),
                ("L'IA montre aussi les mots qui ont augmenté son score. "
                 "Le lien n'a jamais été ouvert.", 3800),
            ],
        )  # fmt: skip

        # --- Email 2: raw email with spoofed sender
        r.scroll_top()
        r.analyse_email_example(
            "Spoofed",
            "Exemple 2 : un email brut avec en-têtes, expéditeur usurpé et pièce jointe.",
            [
                ("<b>98/100 — 9 indicateurs</b> : usurpation de PayPal, Reply-To vers un "
                 "autre domaine, lien trompeur…", 4400),
                ("La pièce jointe « statement.pdf.exe » est identifiée par son nom : "
                 "elle n'est jamais ouverte ni exécutée.", 4200),
            ],
        )  # fmt: skip

        # --- Email 3: legitimate
        r.scroll_top()
        r.analyse_email_example(
            "Legitimate: delivery",
            "Exemple 3 : un avis de livraison légitime.",
            [
                ("<b>✔ Probablement légitime — 23/100.</b> L'IA seule donnait 47 % : "
                 "sans indicateur concret, le moteur ne crie pas au loup.", 5000),
                ("Un score bas n'est jamais présenté comme une garantie de sécurité.", 3000),
            ],
        )  # fmt: skip

        # --- URL analysis
        r.caption("Passons à l'analyse d'URL, entièrement hors ligne.", 1600)
        r.glide_click(page.get_by_role("link", name="URL analysis"))
        r.idle()
        url_box = page.get_by_label("URL to analyse")
        r.glide_click(url_box)
        r.caption("On saisit une adresse suspecte…", 300)
        r.type_text(url_box, "http://paypal.com.secure-login.account-verify.xyz/webscr?cmd=_login")
        r.glide_click(page.get_by_role("button", name="Analyse URL"))
        r.idle()
        r.caption("L'adresse est affichée « désamorcée » (hxxp, [.]) pour qu'on ne "
                  "puisse pas cliquer dessus par erreur.", 4200)  # fmt: skip
        r.scroll_to(".pg-verdict")
        r.caption("<b>✖ 74/100</b> : marque PayPal sur un domaine sans rapport, "
                  "sous-domaines multiples, mots sensibles, pas de HTTPS.", 4800)  # fmt: skip
        r.scroll_top()

        r.load_example("Credential page")
        r.glide_click(page.get_by_role("button", name="Analyse URL"))
        r.idle()
        r.scroll_to(".pg-verdict")
        r.caption("L'astuce « @ » : tout ce qui précède @ est ignoré par le navigateur "
                  "→ <b>⚠ Suspect</b>.", 4000)  # fmt: skip
        r.scroll_top()

        r.caption("Les entrées invalides sont refusées avec un message clair.", 900)
        url_box = page.get_by_label("URL to analyse")
        url_box.fill("")
        r.type_text(url_box, "javascript:alert(1)", every=1)
        r.glide_click(page.get_by_role("button", name="Analyse URL"))
        r.idle()
        r.pause(2600)

        # --- Dashboard
        r.caption("Le tableau de bord se remplit à partir des analyses enregistrées.", 1500)
        r.glide_click(page.get_by_role("link", name="Dashboard"))
        r.idle()
        r.pause(1200)
        r.caption("Indicateurs clés, activité, répartition des verdicts… "
                  "tout est calculé depuis la base SQLite locale.", 4200)  # fmt: skip
        r.scroll_main(480, 1400)
        r.caption("Distribution des scores avec les seuils, et indicateurs les plus "
                  "fréquents.", 3800)  # fmt: skip
        r.scroll_main(520, 1400)
        r.caption("Dernières analyses et état de la plateforme.", 3000)

        # --- History
        r.glide_click(page.get_by_role("link", name="History"))
        r.idle()
        r.caption("L'historique : recherche, filtres par verdict, type et date.", 2600)
        verdict = page.get_by_role("combobox").nth(0)
        r.glide_click(verdict)
        verdict.fill("phishing")
        r.pause(500)
        page.keyboard.press("Enter")
        page.keyboard.press("Escape")
        r.idle()
        r.caption("Filtre « Probablement du phishing ». On peut aussi supprimer des "
                  "entrées (avec confirmation) et exporter en CSV.", 4200)  # fmt: skip
        r.glide_click(page.get_by_role("button", name="Export results (CSV)"), 500)
        r.pause(1300)

        # --- Model evaluation
        r.caption("Enfin, l'évaluation du modèle d'IA.", 1500)
        r.glide_click(page.get_by_role("link", name="Model evaluation"))
        r.idle()
        r.pause(1000)
        r.caption("Métriques réelles sur 1 506 emails jamais vus : précision 0,990, "
                  "rappel 0,987, F1 0,988.", 4400)  # fmt: skip
        r.scroll_main(560, 1400)
        r.caption("Matrice de confusion et courbe ROC (AUC 0,999).", 3400)
        r.scroll_main(620, 1400)
        r.caption("Le moteur complet (IA + règles) est évalué honnêtement, "
                  "limites comprises.", 4000)  # fmt: skip
        r.scroll_main(700, 1400)
        r.caption("Données, méthode anti-fuite, termes influents et limites connues.", 3400)
        r.caption(None, 300)

        # --- Outro card
        page.set_content(OUTRO)
        r.pause(5000)

        ctx.close()
        browser.close()
        return r.frames


def to_mp4(frames: list[tuple[float, Path]], mp4: Path, work: Path) -> None:
    """Assemble the timestamped frames into a constant 25 fps H.264 MP4."""
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    lines = []
    nexts = [t for t, _ in frames[1:]] + [frames[-1][0] + 0.5]
    for (t, path), t_next in zip(frames, nexts, strict=True):
        lines.append(f"file '{path.as_posix()}'")
        lines.append(f"duration {max(t_next - t, 0.001):.4f}")
    lines.append(f"file '{frames[-1][1].as_posix()}'")  # concat demuxer: repeat last frame
    listing = work / "frames.txt"
    listing.write_text("\n".join(lines), encoding="utf-8")
    mp4.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [ffmpeg, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing),
         "-vf", "fps=25,format=yuv420p", "-c:v", "libx264", "-preset", "slow", "-crf", "21",
         "-movflags", "+faststart", str(mp4)],
        check=True,
    )  # fmt: skip


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="pg_video_"))
    try:
        frames = record(work)
        to_mp4(frames, OUTPUT, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    duration = frames[-1][0] - frames[0][0]
    size_mb = OUTPUT.stat().st_size / 1_048_576
    print(f"saved {OUTPUT.relative_to(ROOT)}: {duration:.0f} s, {len(frames)} frames "
          f"({len(frames) / duration:.1f} fps captured), {size_mb:.1f} MB")  # fmt: skip


if __name__ == "__main__":
    main()
