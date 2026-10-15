"""Capture the Kibana dashboard and the correlator timeline into docs/screenshots.

Reads secrets from env (never hard-coded); run on the Windows host which can reach the
management network (192.168.56.10). Requires playwright + chromium.

  ELASTIC_PASSWORD=... CORRELATOR_KEY=... python scripts/shots.py
"""
import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

MGMT = os.getenv("MGMT_IP", "192.168.56.10")
ES_PW = os.getenv("ELASTIC_PASSWORD", "")   # only needed for the Kibana shot
CK = os.environ["CORRELATOR_KEY"]
OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)


def shot_correlator(browser):
    ctx = browser.new_context(
        viewport={"width": 1200, "height": 900},
        http_credentials={"username": "analyst", "password": CK},
        device_scale_factor=2,
    )
    page = ctx.new_page()
    page.goto(f"http://{MGMT}:8088/", wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(500)
    dest = OUT / "stage7-correlator.png"
    page.screenshot(path=str(dest), full_page=True)
    print("wrote", dest)
    ctx.close()


def shot_campaign_timeline(browser):
    """Expand the freshest campaign's per-event table — the attack walkthrough."""
    ctx = browser.new_context(
        viewport={"width": 1280, "height": 900},
        http_credentials={"username": "analyst", "password": CK},
        device_scale_factor=2,
    )
    page = ctx.new_page()
    page.goto(f"http://{MGMT}:8088/", wait_until="networkidle", timeout=30000)
    page.eval_on_selector("section:first-of-type details", "d => d.open = true")
    page.wait_for_timeout(400)
    dest = OUT / "stage9-timeline.png"
    page.locator("section").first.screenshot(path=str(dest))
    print("wrote", dest)
    ctx.close()


def shot_kibana(browser):
    ctx = browser.new_context(viewport={"width": 1680, "height": 1300}, device_scale_factor=1)
    page = ctx.new_page()
    page.goto(f"http://{MGMT}:5601/login", wait_until="domcontentloaded", timeout=60000)
    page.fill('input[name="username"]', "elastic", timeout=30000)
    page.fill('input[name="password"]', ES_PW)
    page.click('[data-test-subj="loginSubmit"]')
    page.wait_for_url("**/app/**", timeout=60000)
    page.goto(f"http://{MGMT}:5601/app/dashboards#/view/mirage-overview",
              wait_until="networkidle", timeout=60000)
    # let the panels fetch + render
    try:
        page.wait_for_selector(".echChart, [data-test-subj='visualizationLoader'], table",
                               timeout=45000)
    except Exception as e:
        print("warn: chart selector wait:", e)
    page.wait_for_timeout(6000)
    # dismiss the "configure publicBaseUrl" toast and any selected table cell
    for sel in ('[data-test-subj="toastCloseButton"]', 'button:has-text("Mute warning")'):
        try:
            page.click(sel, timeout=1500)
        except Exception:
            pass
    page.keyboard.press("Escape")
    page.mouse.click(5, 160)  # empty area under the top bar
    page.wait_for_timeout(1200)
    dest = OUT / "stage3-kibana-dashboard.png"
    page.screenshot(path=str(dest), full_page=True)
    print("wrote", dest)
    ctx.close()


def main():
    # Optional argv picks targets: correlator | timeline | kibana (default: all).
    # MGMT_IP defaults to the management network but can point at a local instance.
    targets = {'correlator': shot_correlator, 'timeline': shot_campaign_timeline,
               'kibana': shot_kibana}
    chosen = [targets[a] for a in sys.argv[1:] if a in targets] or list(targets.values())
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ok = True
        for fn in chosen:
            try:
                fn(browser)
            except Exception as e:
                ok = False
                print(f"ERROR in {fn.__name__}: {e}", file=sys.stderr)
        browser.close()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
