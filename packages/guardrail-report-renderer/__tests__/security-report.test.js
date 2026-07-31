/**
 * @jest-environment jsdom
 */

const fs = require("fs");
const path = require("path");

const securityReportScript = fs.readFileSync(
  path.join(__dirname, "../../../docs/assets/js/security-report.js"),
  "utf8"
);

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
      <h2 id="security-empty-title">Live report pending</h2>
      <p id="security-empty-copy"></p>
    </div>
    <div id="security-dashboard" style="display: none"></div>
  `;
}

async function runSecurityReport({ liveReport, exampleReport, fetchError = null }) {
  mountSecurityReport();

  window.GUARDRAIL_SECURITY_REPORT = liveReport;
  window.GUARDRAIL_EXAMPLE_REPORT_URL = "/example-report.json";
  window.GuardrailReportRenderer = class MockRenderer {
    constructor(container) {
      this.container = container;
    }

    render(report) {
      this.container.dataset.renderedResults = String(report.results.length);
    }
  };

  const fetchMock = jest.fn(() => {
    if (fetchError) return Promise.reject(fetchError);
    return Promise.resolve({
      ok: true,
      json: async () => exampleReport,
    });
  });
  global.fetch = fetchMock;
  window.fetch = fetchMock;

  window.eval(securityReportScript);
  document.dispatchEvent(new Event("DOMContentLoaded"));
  await new Promise((resolve) => setTimeout(resolve, 0));

  return fetchMock;
}

describe("Security Report page state handling", () => {
  afterEach(() => {
    jest.restoreAllMocks();
    delete window.GUARDRAIL_SECURITY_REPORT;
    delete window.GUARDRAIL_EXAMPLE_REPORT_URL;
    delete window.GuardrailReportRenderer;
    delete global.fetch;
    document.body.innerHTML = "";
  });

  test("renders real findings and hides the example notice", async () => {
    const fetchMock = await runSecurityReport({
      liveReport: { results: [{ finding: { rule_id: "live-rule" } }] },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] },
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(document.getElementById("security-live-findings").style.display).toBe("block");
    expect(document.getElementById("security-live-success").style.display).toBe("none");
    expect(document.getElementById("security-example-notice").style.display).toBe("none");
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1");
    expect(document.querySelector(".report-status-label").textContent).toContain("Live src/");
  });

  test("states that the real scan was clean while rendering labeled example data", async () => {
    const fetchMock = await runSecurityReport({
      liveReport: { results: [] },
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] },
    });

    expect(fetchMock).toHaveBeenCalledWith("/example-report.json");
    expect(document.getElementById("security-live-success").style.display).toBe("block");
    expect(document.getElementById("security-example-notice").style.display).toBe("block");
    expect(document.getElementById("security-example-label").textContent).toContain("live scan clean");
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "The real Guardrail scan found no issues"
    );
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "not real repository issues"
    );
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1");
    expect(document.getElementById("security-empty").style.display).toBe("none");
  });

  test("uses clearly labeled example data when the live report is unavailable", async () => {
    await runSecurityReport({
      liveReport: undefined,
      exampleReport: { results: [{ finding: { rule_id: "sample-rule" } }] },
    });

    expect(document.getElementById("security-example-notice").style.display).toBe("block");
    expect(document.getElementById("security-example-label").textContent).toContain(
      "live scan unavailable"
    );
    expect(document.getElementById("security-example-copy").textContent).toContain(
      "committed synthetic data"
    );
    expect(document.getElementById("security-dashboard").dataset.renderedResults).toBe("1");
    expect(document.getElementById("security-empty").style.display).toBe("none");
  });

  test("keeps a clean live result honest when example data cannot load", async () => {
    await runSecurityReport({
      liveReport: { results: [] },
      exampleReport: null,
      fetchError: new Error("network unavailable"),
    });

    expect(document.getElementById("security-live-success").style.display).toBe("none");
    expect(document.getElementById("security-empty").style.display).toBe("block");
    expect(document.getElementById("security-empty-title").textContent).toBe(
      "The real Guardrail scan found no issues"
    );
    expect(document.getElementById("security-empty-copy").textContent).toContain(
      "No example findings are being shown"
    );
    expect(document.getElementById("security-dashboard").style.display).toBe("none");
  });

  test("reports both sources unavailable without showing an unlabeled dashboard", async () => {
    await runSecurityReport({
      liveReport: undefined,
      exampleReport: null,
      fetchError: new Error("network unavailable"),
    });

    expect(document.getElementById("security-example-notice").style.display).toBe("none");
    expect(document.getElementById("security-empty").style.display).toBe("block");
    expect(document.getElementById("security-empty-title").textContent).toBe(
      "Security report unavailable"
    );
    expect(document.getElementById("security-empty-copy").textContent).toContain(
      "live Guardrail scan and the committed example dashboard could not be loaded"
    );
    expect(document.getElementById("security-dashboard").style.display).toBe("none");
  });
});
