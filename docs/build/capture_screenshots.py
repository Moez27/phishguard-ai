"""Capture screenshots of every PhishGuard AI feature into docs/screenshots/.

The history starts empty and every record is created through the interface
(the 8 built-in synthetic examples), so the Dashboard and History screenshots
show exactly what a user would see after running them.

Run from the project root:
    .\\.venv\\Scripts\\python.exe docs\\build\\capture_screenshots.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app_driver import (  # noqa: E402
    SCREENSHOTS,
    content_height,
    goto_page,
    load_example,
    reset_demo_database,
    running_app,
    wait_idle,
)
from playwright.sync_api import sync_playwright  # noqa: E402

PORT = 8510
WIDTH, HEIGHT = 1440, 900
SCALE = 1.5  # crisp images for print

EMAILS = [  # (option prefix, screenshot name or None)
    ("Credential", "03_email_result_phishing"),
    ("Spoofed", "04_email_result_spoof"),
    ("Legitimate: colleague", None),
    ("Legitimate: delivery", "05_email_result_legitimate"),
]
URLS = [
    ("Brand on", "06_url_result"),
    ("Raw IP", None),
    ("Credential page", None),
    ("Ordinary", None),
]


def park_mouse(page) -> None:
    """Move the pointer away so no hover toolbar/tooltip appears in the capture."""
    page.mouse.move(5, HEIGHT - 5)
    page.wait_for_timeout(250)


def _section_clip(page, start: str, end: str | None) -> dict | None:
    """Rectangle of the main column between two elements (selectors), in CSS pixels."""
    block = page.locator('[data-testid="stMainBlockContainer"]').first.bounding_box()
    top = page.locator(start).first.bounding_box()
    if not block or not top:
        return None
    if end:
        bottom_box = page.locator(end).first.bounding_box()
        bottom = bottom_box["y"] - 10 if bottom_box else block["y"] + block["height"]
    else:
        bottom = block["y"] + block["height"] - 40
    x = max(0, block["x"] + 40)
    return {"x": x, "y": max(0, top["y"] - 14), "width": block["width"] - 80,
            "height": max(50, bottom - top["y"] + 14)}  # fmt: skip


def shot(
    page,
    name: str,
    full: bool = True,
    max_height: int = 9000,
    sections: list[tuple[str, str, str | None]] = (),
) -> None:
    """Screenshot the page. Streamlit scrolls inside a container, so for a full-page
    capture the viewport is temporarily enlarged to the content height.

    ``sections`` = (name, start selector, end selector or None): extra crops of the
    main column (without the sidebar) used in the printed documents.
    """
    path = SCREENSHOTS / f"{name}.png"
    park_mouse(page)
    if full:
        h = HEIGHT
        for _ in range(4):  # layout can change once the viewport is taller: re-measure
            target = min(max(HEIGHT, content_height(page) + 60), max_height)
            if abs(target - h) < 5:
                break
            h = target
            page.set_viewport_size({"width": WIDTH, "height": h})
            wait_idle(page, settle_ms=600)
        page.screenshot(path=str(path))
        for sec_name, start, end in sections:
            clip = _section_clip(page, start, end)
            if clip:
                page.screenshot(path=str(SCREENSHOTS / f"{sec_name}.png"), clip=clip)
                print("saved", f"{sec_name}.png")
        page.set_viewport_size({"width": WIDTH, "height": HEIGHT})
        wait_idle(page, settle_ms=300)
    else:
        page.screenshot(path=str(path))
    print("saved", path.name)


def element_shot(page, locator, name: str) -> None:
    locator.scroll_into_view_if_needed()
    park_mouse(page)
    locator.screenshot(path=str(SCREENSHOTS / f"{name}.png"))
    print("saved", f"{name}.png")


def main() -> None:
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    reset_demo_database()
    with running_app(PORT) as url, sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        ctx = browser.new_context(
            viewport={"width": WIDTH, "height": HEIGHT},
            device_scale_factor=SCALE,
            color_scheme="dark",
            locale="en-US",
        )
        page = ctx.new_page()

        # Empty dashboard (first launch)
        goto_page(page, url, "")
        shot(page, "00_dashboard_empty", full=False)

        # Email analysis: input form with an example, then every example
        goto_page(page, url, "email_analysis")
        for i, (prefix, name) in enumerate(EMAILS):
            load_example(page, "Try a built-in example", prefix)
            if i == 0:
                shot(page, "02_email_input", full=False)
            page.get_by_role("button", name="Analyse email").click()
            wait_idle(page)
            if name:
                shot(page, name, sections=[(f"s{name[:2]}_result", ".pg-verdict", None)])
            if i == 0:
                element_shot(page, page.locator(".pg-verdict").first, "03b_verdict_banner")
            if i == 1:
                element_shot(
                    page,
                    page.locator(".pg-card").filter(has=page.locator(".pg-signal")).first,
                    "04b_spoof_indicators",
                )

        # URL analysis: every example
        goto_page(page, url, "url_analysis")
        for prefix, name in URLS:
            load_example(page, "Try a built-in example", prefix)
            page.get_by_role("button", name="Analyse URL").click()
            wait_idle(page)
            if name:
                page.get_by_text("Extracted features").click()
                wait_idle(page)
                shot(page, name, sections=[("s06_url_result", "text=Analysed address", None)])

        # Input validation (error handling) — not saved to the history
        page.get_by_label("URL to analyse").fill("javascript:alert(1)")
        page.get_by_role("button", name="Analyse URL").click()
        wait_idle(page)
        page.locator('[data-testid="stMain"]').evaluate("m => m.scrollTo(0, 0)")
        shot(page, "07_url_error", full=False)

        # Dashboard with the 8 analyses
        goto_page(page, url, "")
        page.wait_for_timeout(1500)  # chart animation
        shot(
            page,
            "01_dashboard",
            sections=[
                ("s01_dashboard_charts", ".pg-header", 'h4:has-text("Latest analyses")'),
                ("s01_dashboard_table", 'h4:has-text("Latest analyses")', None),
            ],
        )
        shot(page, "01b_dashboard_top", full=False)

        # History, filtered history with details, delete dialog
        goto_page(page, url, "history")
        page.wait_for_timeout(800)
        shot(page, "08_history")
        verdict = page.get_by_role("combobox").nth(0)
        verdict.click()
        verdict.fill("phishing")
        page.keyboard.press("Enter")
        page.keyboard.press("Escape")
        wait_idle(page)
        grid = page.locator('[data-testid="stDataFrame"]').first
        box = grid.bounding_box()
        if box:  # tick the first data row's selection checkbox (left column)
            page.mouse.click(box["x"] + 18, box["y"] + 35 + 17)
            wait_idle(page)
        shot(
            page,
            "09_history_filtered_details",
            sections=[("s09_history_details", '[data-testid="stDataFrame"]', None)],
        )
        delete_btn = page.get_by_role("button", name="Delete selected")
        if delete_btn.count():
            delete_btn.first.click()
            wait_idle(page)
            shot(page, "10_history_delete_dialog", full=False)
            page.keyboard.press("Escape")  # cancel: nothing is deleted
            wait_idle(page)

        # Model evaluation and About
        goto_page(page, url, "model_evaluation")
        page.wait_for_timeout(1500)
        shot(
            page,
            "11_model_evaluation",
            sections=[
                ("s11_eval_metrics", 'h3:has-text("AI model")', 'h3:has-text("Model comparison")'),
                (
                    "s11_eval_engine",
                    'h3:has-text("Model comparison")',
                    'h3:has-text("Data and method")',
                ),
                (
                    "s11_eval_data",
                    'h3:has-text("Data and method")',
                    'h3:has-text("Known limitations")',
                ),
            ],
        )
        goto_page(page, url, "about")
        shot(page, "12_about")

        # Mobile layout
        mobile = browser.new_context(
            viewport={"width": 390, "height": 844},
            device_scale_factor=2,
            is_mobile=True,
            has_touch=True,
            color_scheme="dark",
        )
        mpage = mobile.new_page()
        goto_page(mpage, url, "")
        mpage.wait_for_timeout(1500)
        mpage.screenshot(path=str(SCREENSHOTS / "13_mobile_dashboard.png"))
        print("saved 13_mobile_dashboard.png")
        browser.close()


def check_screenshots() -> list[str]:
    """Flag captures that show Streamlit's grey loading skeleton instead of the app.

    The app's sidebar is navy (blue channel clearly above red); the skeleton is
    neutral grey. Returns the names of suspicious files.
    """
    from PIL import Image

    bad = []
    for path in sorted(SCREENSHOTS.glob("*.png")):
        if path.name.startswith(("03b_", "04b_")):  # element crops, no sidebar
            continue
        with Image.open(path) as img:
            r, g, b = img.convert("RGB").getpixel((10, img.height // 2))[:3]
        if b - r < 10:
            bad.append(path.name)
    return bad


if __name__ == "__main__":
    main()
    problems = check_screenshots()
    print("CHECK:", "all screenshots show the app" if not problems else f"SKELETON in {problems}")
