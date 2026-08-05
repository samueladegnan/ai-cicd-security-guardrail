/**
 * @jest-environment jsdom
 */

const fs = require("fs")
const path = require("path")

const securityReportScript = fs.readFileSync(
  path.join(__dirname, "../../../docs/assets/js/security-report.js"),
  "utf8"
)

function mountSecurityReport() {
  document.body.innerHTML = `
    <div class="report-status-label"></div>
    <div id="security-live-findings" style="display: none"></div>
    <div id="security-example-notice" style="display: none">
      <div class="example-report-notice__status">
        <div id="security-example-label"></div>
        <span id="security-example-inline-copy"></span>
      </div>
      <h2 id="security-example-title"></h2>
      <p id="security-example-copy"></p>
    </div>
    <div id="security-empty" style="display: none">
      <h2 id="security-empty-title">Report pending</h2>
      <p id="security-empty-copy"></p>
    </div>
    <div id="security-dashboard" style="display: none"></div>
  `
}

async function runSecurityReport({ liveReport, exampleReport, fetchError = null }) {
  mountSecurityReport()

  window.GUARDRAIL_SECURITY_REPORT = liveReport
  window.GUARDRAIL_EXAMPLE_REPORT_URL = "/example-report.json"
  window.GuardrailReportRenderer = class MockRenderer {
    constructor(container) {
      this.container = container
    }

    render(report) {
      this.container.dataset.renderedResults = String(report.results.length)
      this.container.dataset.summary = JSON.stringify(report.summary || {})
    }
  }

  const fetchMock = jest.fn(() => {
    if (fetchError) return Promise.reject(fetchError)
    return Promise.resolve({
      ok: true,
      json: async () => exampleReport
    })
  })
  global.fetch = fetchMock
  window.fetch = fetchMock

  window.eval(securityReportScript)
  document.dispatchEvent(new Event("DOMContentLoaded"))
  await new Promise((resolve) => setTimeout(resolve, 0))

  return fetchMock
}

describe("Security report page state handling", () => {
  afterEach(() => {
    jest.restoreAllMocks()
    delete window.GUARDRAIL_SECURITY_REPORT
    delete window.GUARDRAIL_EXAMPLE_REPORT_URL
    delete window.GuardrailReportRenderer
    delete global.fetch
    document.body.innerHTML = ""
  })

  test("renders scoped findings and hides the synthetic notice", async () => {
    const fetchMock = await runSecurityReport({
      liveReport: { results: [{ finding: { rule_id: "scoped-rule", file_path: "src/app.py" } }] },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(fetchMock).not.toHaveBeenCalled()
    expect(document.getElementById("security-live-findings").style.display).toBe("block")
    expect(document.getElementById("security-example-notice").style.display).toBe("none")
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1")
    expect(document.querySelector(".report-status-label").textContent).toContain("Scoped src/")
  })

  test("ignores intentional sample-code findings and shows synthetic data", async () => {
    const fetchMock = await runSecurityReport({
      liveReport: {
        results: [
          { finding: { file_path: "sample_code/vulnerable.c" } },
          { finding: { file_path: "sample_code/false_positive.c" } }
        ]
      },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(fetchMock).toHaveBeenCalledWith("/example-report.json")
    expect(document.getElementById("security-live-findings").style.display).toBe("none")
    expect(document.getElementById("security-example-notice").style.display).toBe("block")
    expect(document.getElementById("security-example-label").textContent).toBe(
      "No real issues found"
    )
    expect(document.getElementById("security-example-inline-copy").textContent).toBe(
      "Example data is displayed because no real issues were found."
    )
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1")
  })

  test("normalizes paths and enforces the src boundary", async () => {
    await runSecurityReport({
      liveReport: {
        results: [
          { finding: { file_path: ".\\src\\windows.py", rule_id: "windows" } },
          { finding: { file_path: "./src/relative.py", rule_id: "relative" } },
          { finding: { file_path: "src-other/not-scoped.py", rule_id: "wrong-root" } },
          { finding: { file_path: "../src/traversal.py", rule_id: "traversal" } },
          { finding: { file_path: "src/sample_code/example.py", rule_id: "nested-sample" } },
          { finding: { rule_id: "missing-path" } }
        ]
      },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(document.getElementById("security-live-findings").style.display).toBe("block")
    expect(document.getElementById("security-example-notice").style.display).toBe("none")
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("2")
  })

  test("renders only in-scope src findings from a mixed report", async () => {
    await runSecurityReport({
      liveReport: {
        results: [
          { finding: { file_path: "src/app.py", rule_id: "scoped-rule" }, verdict: "HIGH_PRIORITY" },
          { finding: { file_path: "sample_code/vulnerable.c" }, verdict: "HIGH_PRIORITY" }
        ]
      },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(document.getElementById("security-live-findings").style.display).toBe("block")
    expect(document.getElementById("security-example-notice").style.display).toBe("none")
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1")
    expect(JSON.parse(document.getElementById("security-dashboard").dataset.summary)).toEqual({
      total: 1,
      high_priority: 1,
      false_positive: 0,
      unclear: 0
    })
  })

  test("states that the scoped scan was clean while rendering synthetic data", async () => {
    const fetchMock = await runSecurityReport({
      liveReport: { results: [] },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(fetchMock).toHaveBeenCalledWith("/example-report.json")
    expect(document.getElementById("security-example-notice").style.display).toBe("block")
    expect(document.getElementById("security-example-label").textContent).toBe(
      "No real issues found"
    )
    expect(document.getElementById("security-example-inline-copy").textContent).toBe(
      "Example data is displayed because no real issues were found."
    )
    expect(document.getElementById("security-example-title").textContent).toBe(
      "Example data is shown instead"
    )
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "findings below are synthetic examples"
    )
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "not repository issues"
    )
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1")
    expect(document.getElementById("security-empty").style.display).toBe("none")
  })

  test("does not claim a clean scan when the scoped report is unavailable", async () => {
    await runSecurityReport({
      liveReport: undefined,
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(document.getElementById("security-example-notice").style.display).toBe("block")
    expect(document.getElementById("security-example-label").textContent).toContain(
      "Scan unavailable"
    )
    expect(document.getElementById("security-example-inline-copy").textContent).toBe(
      "Example findings are shown for interface demonstration."
    )
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "cannot confirm whether the repository has findings"
    )
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1")
    expect(document.getElementById("security-empty").style.display).toBe("none")
  })

  test("keeps a clean scoped result honest when synthetic data cannot load", async () => {
    const consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {})
    await runSecurityReport({
      liveReport: { results: [] },
      exampleReport: null,
      fetchError: new Error("network unavailable")
    })

    expect(document.getElementById("security-empty").style.display).toBe("block")
    expect(document.getElementById("security-empty-title").textContent).toBe(
      "No real issues found"
    )
    expect(document.getElementById("security-empty-copy").textContent).toContain(
      "example data could not be loaded"
    )
    expect(document.getElementById("security-dashboard").style.display).toBe("none")
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      "Unable to load the synthetic security report",
      expect.any(Error)
    )
  })

  test("reports both sources unavailable without showing an unlabeled dashboard", async () => {
    const consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {})
    await runSecurityReport({
      liveReport: undefined,
      exampleReport: null,
      fetchError: new Error("network unavailable")
    })

    expect(document.getElementById("security-example-notice").style.display).toBe("none")
    expect(document.getElementById("security-empty").style.display).toBe("block")
    expect(document.getElementById("security-empty-title").textContent).toBe(
      "Security report unavailable"
    )
    expect(document.getElementById("security-empty-copy").textContent).toContain(
      "scoped self-assessment and example data could not be loaded"
    )
    expect(document.getElementById("security-dashboard").style.display).toBe("none")
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      "Unable to load the synthetic security report",
      expect.any(Error)
    )
  })
})
