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
    <div id="security-live-success" style="display: none"></div>
    <div id="security-live-findings" style="display: none"></div>
    <div id="security-example-notice" style="display: none">
      <div id="security-example-label"></div>
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
      liveReport: { results: [{ finding: { rule_id: "scoped-rule" } }] },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(fetchMock).not.toHaveBeenCalled()
    expect(document.getElementById("security-live-findings").style.display).toBe("block")
    expect(document.getElementById("security-live-success").style.display).toBe("none")
    expect(document.getElementById("security-example-notice").style.display).toBe("none")
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1")
    expect(document.querySelector(".report-status-label").textContent).toContain("Scoped src/")
  })

  test("states that the scoped scan was clean while rendering synthetic data", async () => {
    const fetchMock = await runSecurityReport({
      liveReport: { results: [] },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(fetchMock).toHaveBeenCalledWith("/example-report.json")
    expect(document.getElementById("security-live-success").style.display).toBe("block")
    expect(document.getElementById("security-example-notice").style.display).toBe("block")
    expect(document.getElementById("security-example-label").textContent).toContain("scoped scan clean")
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "scoped self-assessment returned no findings"
    )
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "not repository issues"
    )
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1")
    expect(document.getElementById("security-empty").style.display).toBe("none")
  })

  test("uses clearly labeled synthetic data when the scoped report is unavailable", async () => {
    await runSecurityReport({
      liveReport: undefined,
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] }
    })

    expect(document.getElementById("security-example-notice").style.display).toBe("block")
    expect(document.getElementById("security-example-label").textContent).toContain(
      "scan unavailable"
    )
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "committed synthetic data"
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

    expect(document.getElementById("security-live-success").style.display).toBe("none")
    expect(document.getElementById("security-empty").style.display).toBe("block")
    expect(document.getElementById("security-empty-title").textContent).toBe(
      "Scoped self-assessment is clean"
    )
    expect(document.getElementById("security-empty-copy").textContent).toContain(
      "synthetic dashboard could not be loaded"
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
      "scoped self-assessment and synthetic dashboard could not be loaded"
    )
    expect(document.getElementById("security-dashboard").style.display).toBe("none")
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      "Unable to load the synthetic security report",
      expect.any(Error)
    )
  })
})
