import sys
from pathlib import Path
from playwright.sync_api import sync_playwright


URL = "http://localhost:4000/ai-cicd-security-guardrail/demo/"
SCREENSHOT_DIR = Path("screenshots")
SCREENSHOT_PATH = SCREENSHOT_DIR / "demo-screenshot.png"
CUSTOM_SARIF = """{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2-1-0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Demo"}},
    "results": [{
      "ruleId": "CWE-121",
      "message": {"text": "Possible buffer overflow."},
      "level": "error",
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/main.c"}, "region": {"startLine": 10, "startColumn": 5}}}]
    }]
  }]
}"""


def _read_metrics(page):
    return {
        "total": page.locator('[data-metric="total"]').text_content().strip(),
        "high": page.locator('[data-metric="high"]').text_content().strip(),
        "fp": page.locator('[data-metric="fp"]').text_content().strip(),
        "unclear": page.locator('[data-metric="unclear"]').text_content().strip(),
    }


def _wait_for_results(page, label="results"):
    page.locator(".summary-card").wait_for(state="visible", timeout=15000)
    page.locator(".results-card").wait_for(state="visible", timeout=5000)


def _screenshot_path(name: str) -> Path:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    return SCREENSHOT_DIR / name


def main() -> int:
    console_errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(viewport={"width": 1400, "height": 900})
            page = context.new_page()

            def handle_console(msg):
                if msg.type == "error":
                    console_errors.append(msg.text)

            page.on("console", handle_console)
            page.on("pageerror", lambda exc: console_errors.append(str(exc)))

            try:
                page.goto(URL, wait_until="networkidle")
            except Exception as exc:
                print(f"FAILED to load {URL}: {exc}")
                return 1

            # Sample report flow
            run_button = page.locator("#guardrail-run")
            if run_button.count() == 0:
                print("FAILED: Run button not found")
                return 1

            run_button.click()
            _wait_for_results(page, "sample")

            metrics = _read_metrics(page)
            rows = page.locator(".guardrail-table tbody tr[role='button']").count()

            page.screenshot(path=_screenshot_path("demo-screenshot.png"))
            print(f"Screenshot saved to {SCREENSHOT_PATH}")
            print(f"Sample metrics: {metrics}")
            print(f"Sample result rows: {rows}")

            if metrics["total"] == "0" or rows == 0:
                print("FAILED: Demo did not produce expected results.")
                return 1

            # Custom (client-side) input flow
            page.locator("#guardrail-reset").click()
            page.locator("#guardrail-input").fill(CUSTOM_SARIF)
            page.locator("#guardrail-run").click()
            _wait_for_results(page, "custom")

            custom_total = page.locator('[data-metric="total"]').text_content().strip()
            custom_rows = page.locator(".guardrail-table tbody tr[role='button']").count()
            first_loc = page.locator(".guardrail-table tbody tr[role='button'] td.finding-loc").first.text_content()
            first_verdict = page.locator(".guardrail-table tbody tr[role='button'] td.verdict-cell .guardrail-badge").first.text_content().strip()

            print(f"Custom metrics: total={custom_total}, rows={custom_rows}, first_loc={first_loc!r}, verdict={first_verdict!r}")
            if custom_total != "1" or "src/main.c" not in first_loc or "High" not in first_verdict:
                print("FAILED: Custom input did not render correctly.")
                page.screenshot(path=_screenshot_path("demo-failed-custom.png"))
                return 1

            if console_errors:
                print("Console errors:")
                for err in console_errors:
                    print(f"  - {err}")
                return 1

            # A narrow viewport smoke check catches header wrapping and page overflow
            # without duplicating the full interaction flow.
            mobile_errors = []
            mobile_context = browser.new_context(viewport={"width": 390, "height": 844})
            mobile = mobile_context.new_page()
            mobile.on("console", lambda msg: mobile_errors.append(msg.text) if msg.type == "error" else None)
            mobile.on("pageerror", lambda exc: mobile_errors.append(str(exc)))
            try:
                mobile.goto(URL, wait_until="networkidle")
                overflow = mobile.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
                if overflow:
                    print("FAILED: Mobile page has horizontal overflow.")
                    mobile.screenshot(path=_screenshot_path("demo-failed-mobile.png"))
                    return 1
                mobile.locator("#guardrail-run").wait_for(state="visible", timeout=5000)
                if mobile_errors:
                    print("Mobile console errors:")
                    for err in mobile_errors:
                        print(f"  - {err}")
                    return 1
            finally:
                mobile_context.close()

            print("Mobile layout: no horizontal overflow; Run button visible; no console errors.")
            print("SUCCESS: Demo loaded, produced results, and passed the mobile smoke check.")
            return 0
        finally:
            browser.close()


if __name__ == "__main__":
    sys.exit(main())
