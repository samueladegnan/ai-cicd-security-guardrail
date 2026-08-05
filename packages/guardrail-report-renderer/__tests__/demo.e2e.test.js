/**
 * End-to-end test for the browser demo page.
 *
 * This test assumes the Jekyll docs site is already running at
 * http://localhost:4000/ai-cicd-security-guardrail/demo/.
 */

const { test, expect } = require("@playwright/test")

const DEMO_URL = process.env.DEMO_URL || "http://localhost:4000/ai-cicd-security-guardrail/demo/"

test.describe("Browser demo", () => {
  test("rejects empty and malformed custom input cleanly", async ({ page }) => {
    const consoleErrors = []
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text())
    })
    page.on("pageerror", (error) => consoleErrors.push(String(error)))

    await page.goto(DEMO_URL, { waitUntil: "networkidle" })
    await page.selectOption("#guardrail-sample", "")
    await page.fill("#guardrail-input", "   \n  ")
    await page.click("#guardrail-run")
    await expect(page.locator("#guardrail-status")).toContainText("Please provide report content to run triage.")
    await expect(page.locator("#pipeline-status-text")).toContainText("Ready")

    await page.fill("#guardrail-input", '{"runs":[]}')
    await page.click("#guardrail-run")
    await expect(page.locator("#guardrail-status")).toContainText("Triage complete")

    await page.fill("#guardrail-input", '{"runs":[{')
    await page.click("#guardrail-run")
    await expect(page.locator("#guardrail-status")).toContainText("Could not parse report. Please check the JSON syntax.")
    await expect(page.locator("#guardrail-results-panel")).toBeHidden()

    await page.selectOption("#guardrail-format", "cppcheck")
    await page.fill("#guardrail-input", "<results><errors>")
    await page.click("#guardrail-run")
    await expect(page.locator("#guardrail-status")).toContainText("Could not parse report. Please check the XML syntax.")
    await expect(page.locator("#guardrail-results-panel")).toBeHidden()
    expect(consoleErrors).toHaveLength(0)
  })

  test("loads a selected sample and renders its dashboard", async ({ page }) => {
    const errors = []
    page.on("console", (msg) => {
      if (msg.type() === "error") errors.push(msg.text())
    })

    await page.goto(DEMO_URL, { waitUntil: "networkidle" })
    await page.selectOption("#guardrail-sample", "semgrep")
    await expect(page.locator("#guardrail-input")).toHaveValue(/jwt-none-alg/)
    await expect(page.locator("#input-source-note")).toContainText("committed sample")
    await expect(page.locator("#guardrail-status")).toContainText("loaded")
    await page.click("#guardrail-run")
    await page.waitForSelector(".summary-card", { timeout: 10000 })
    await expect(page.locator('[data-metric="total"]')).toHaveText("5")
    expect(errors).toHaveLength(0)
  })

  test("triages edited sample text as browser input", async ({ page }) => {
    await page.goto(DEMO_URL, { waitUntil: "networkidle" })
    await page.selectOption("#guardrail-sample", "semgrep")
    await expect(page.locator("#guardrail-input")).toHaveValue(/jwt-none-alg/)
    await page.fill(
      "#guardrail-input",
      JSON.stringify({
        version: "2.1.0",
        runs: [{ results: [{ ruleId: "custom-rule", message: { text: "Unused local value" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/example.js" }, region: { startLine: 4 } } }] }] }]
      })
    )
    await page.click("#guardrail-run")
    await page.waitForSelector(".summary-card", { timeout: 10000 })
    await expect(page.locator('[data-metric="total"]')).toHaveText("1")
    await expect(page.locator("#guardrail-status")).toContainText("deterministic approximation")
  })

  test("loads custom SARIF and renders expandable findings", async ({ page }) => {
    const errors = []
    page.on("console", (msg) => {
      if (msg.type() === "error") errors.push(msg.text())
    })

    await page.goto(DEMO_URL, { waitUntil: "networkidle" })
    await page.selectOption("#guardrail-sample", "")
    await page.fill(
      "#guardrail-input",
      JSON.stringify({
        version: "2.1.0",
        runs: [{ results: [{ ruleId: "CWE-121", message: { text: "Buffer overflow" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/main.c" }, region: { startLine: 10 } } }] }] }]
      })
    )
    await page.click("#guardrail-run")
    await page.waitForSelector(".summary-card", { timeout: 10000 })
    await expect(page.locator('[data-metric="total"]')).toHaveText("1")

    const row = page.locator(".guardrail-table tbody tr[role='button']").first()
    await row.click()
    await expect(page.locator(".detail-row").first()).toBeVisible()
    expect(errors).toHaveLength(0)
  })
})
