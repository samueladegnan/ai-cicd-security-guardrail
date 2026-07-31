/**
 * End-to-end test for the live demo page.
 *
 * This test assumes the Jekyll docs site is already running at
 * http://localhost:4000/ai-cicd-security-guardrail/demo/.
 *
 * To run locally:
 *   cd docs && docker compose up -d
 *   cd packages/guardrail-report-renderer && npm run test:e2e
 */

const { test, expect } = require("@playwright/test");

const DEMO_URL = process.env.DEMO_URL || "http://localhost:4000/ai-cicd-security-guardrail/demo/";

test.describe("Live demo", () => {
  test("rejects empty and malformed custom input cleanly", async ({ page }) => {
    const consoleErrors = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (error) => consoleErrors.push(String(error)));

    await page.goto(DEMO_URL, { waitUntil: "networkidle" });

    await page.selectOption("#guardrail-sample", "");
    await page.fill("#guardrail-input", "   \n  ");
    await page.click("#guardrail-run");
    await expect(page.locator("#guardrail-status")).toContainText("Please provide report content to run triage.");
    await expect(page.locator("#pipeline-status-text")).toContainText("Ready");

    // First render a valid report so the test also verifies stale results are cleared.
    await page.fill("#guardrail-input", '{"runs":[]}');
    await page.click("#guardrail-run");
    await expect(page.locator("#guardrail-status")).toContainText("Triage complete");

    await page.fill("#guardrail-input", '{"runs":[{');
    await page.click("#guardrail-run");
    await expect(page.locator("#guardrail-status")).toContainText("Could not parse report. Please check the JSON syntax.");
    await expect(page.locator("#guardrail-results-panel")).toBeHidden();

    await page.selectOption("#guardrail-format", "cppcheck");
    await page.fill("#guardrail-input", "<results><errors>");
    await page.click("#guardrail-run");
    await expect(page.locator("#guardrail-status")).toContainText("Could not parse report. Please check the XML syntax.");
    await expect(page.locator("#guardrail-results-panel")).toBeHidden();
    expect(consoleErrors).toHaveLength(0);
  });

  test("loads, runs triage, and renders the dashboard", async ({ page }) => {
    const errors = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        errors.push(msg.text());
      }
    });

    await page.goto(DEMO_URL, { waitUntil: "networkidle" });

    // Verify the demo input is present
    await expect(page.locator("#guardrail-run")).toBeVisible();

    // Click Run Triage and wait for the dashboard
    await page.click("#guardrail-run");
    await page.waitForSelector(".summary-card", { timeout: 10000 });

    // Verify executive summary metric cards
    await expect(page.locator('[data-metric="total"]')).toBeVisible();
    await expect(page.locator('[data-metric="high"]')).toBeVisible();
    await expect(page.locator('[data-metric="fp"]')).toBeVisible();
    await expect(page.locator('[data-metric="unclear"]')).toBeVisible();

    // Verify the results table has findings
    const rows = page.locator(".guardrail-table tbody tr[role='button']");
    await expect(rows.first()).toBeVisible();
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Click the first finding row to expand details
    await rows.first().click();
    await expect(page.locator(".detail-row").first()).toBeVisible();

    // No console errors
    expect(errors).toHaveLength(0);
  });
});
