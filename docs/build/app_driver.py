"""Helpers to run PhishGuard AI in a separate instance and drive it with Playwright.

The instance uses its own demo database (docs/build/demo.db, git-ignored), filled
with the built-in synthetic examples by scripts/seed_demo.py, so the user's real
history is never touched. The browser is the Microsoft Edge installed on Windows
(Playwright "msedge" channel): no browser download is needed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = Path(__file__).resolve().parent
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
DEMO_DB = BUILD / "demo.db"
SCREENSHOTS = ROOT / "docs" / "screenshots"
MEDIA = ROOT / "docs" / "media"


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["PHISHGUARD_DB_PATH"] = str(DEMO_DB)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def seed_demo_database() -> None:
    """Reset the demo database and add the 8 built-in examples (real engine)."""
    subprocess.run(
        [str(PYTHON), "-m", "scripts.seed_demo", "--reset", "--yes"],
        cwd=ROOT,
        env=_env(),
        check=True,
        stdout=subprocess.DEVNULL,
    )


@contextmanager
def running_app(port: int):
    """Start `streamlit run app.py` on localhost:<port> and stop it afterwards."""
    proc = subprocess.Popen(
        [str(PYTHON), "-m", "streamlit", "run", "app.py", "--server.headless", "true",
         "--server.port", str(port), "--server.address", "localhost"],
        cwd=ROOT,
        env=_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )  # fmt: skip
    url = f"http://localhost:{port}"
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{url}/_stcore/health", timeout=2) as r:  # noqa: S310
                    if r.status == 200:
                        break
            except OSError:
                time.sleep(0.5)
        else:
            raise RuntimeError("Streamlit did not start")
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def wait_idle(page, settle_ms: int = 700, timeout_s: float = 60) -> None:
    """Wait until Streamlit has finished running the script and the page is stable."""
    page.wait_for_timeout(300)
    deadline = time.time() + timeout_s
    quiet_since = None
    while time.time() < deadline:
        running = page.locator('[data-testid="stStatusWidget"]').count() > 0
        skeleton = page.locator('[data-testid="stSkeleton"]').count() > 0
        if running or skeleton:
            quiet_since = None
        elif quiet_since is None:
            quiet_since = time.time()
        elif (time.time() - quiet_since) * 1000 >= settle_ms:
            return
        page.wait_for_timeout(100)


def main_scroller(page):
    return page.locator('[data-testid="stMain"]').first


def content_height(page) -> int:
    """Full height of the scrollable main area (Streamlit scrolls inside stMain)."""
    return int(
        page.evaluate(
            "() => { const b = document.querySelector('[data-testid=\"stMainBlockContainer\"]');"
            " const m = document.querySelector('[data-testid=\"stMain\"]');"
            " if (b && m) return b.getBoundingClientRect().bottom - m.getBoundingClientRect().top"
            " + m.scrollTop;"
            " return document.body.scrollHeight; }"
        )
    )


def reset_demo_database() -> None:
    """Start from an empty demo history (the capture creates every record via the UI)."""
    if DEMO_DB.exists():
        DEMO_DB.unlink()


def goto_page(page, base_url: str, path: str) -> None:
    page.goto(f"{base_url}/{path}", wait_until="domcontentloaded")
    # Every PhishGuard page renders a header; until then Streamlit shows a grey
    # loading skeleton, which must never end up in a screenshot or the video.
    page.wait_for_selector(".pg-header h1", state="visible", timeout=90_000)
    wait_idle(page)


def load_example(page, expander_text: str, option_prefix: str) -> None:
    """Open the 'Try a built-in example' expander and choose an example."""
    combo = page.get_by_label("Synthetic examples", exact=False).first
    if not combo.is_visible():  # expander closed: open it (clicking again would close it)
        page.get_by_text(expander_text, exact=False).first.click()
        page.wait_for_timeout(400)
    combo.click()
    combo.fill(option_prefix)
    page.keyboard.press("Enter")
    wait_idle(page)


if __name__ == "__main__":
    sys.exit("This module is imported by capture_screenshots.py and record_demo.py")
