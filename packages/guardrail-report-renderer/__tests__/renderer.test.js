/**
 * @jest-environment jsdom
 */

const GuardrailReportRenderer = require("../src/index.js");

const sampleReport = {
  summary: {
    total: 3,
    high_priority: 1,
    false_positive: 1,
    unclear: 1,
  },
  results: [
    {
      finding: {
        file_path: "src/app.js",
        line: 42,
        column: 5,
        rule_id: "no-eval",
        cwe: "CWE-94",
        severity: "HIGH",
        message: "Dangerous use of eval",
      },
      verdict: "HIGH_PRIORITY",
      confidence: 0.95,
      reasoning: "eval() can execute arbitrary attacker-controlled code.",
      remediation: "Remove eval() and validate input with a safe parser.",
      compliance_hits: [{ framework: "cert_c", rule_id: "ERR34-C" }],
    },
    {
      filePath: "src/utils.js",
      line: 10,
      ruleId: "unused-var",
      cwe: "",
      severity: "LOW",
      message: "Unused variable 'x'",
      verdict: "FALSE_POSITIVE",
      confidence: 0.88,
      reasoning: "Stylistic warning, not a security risk.",
      remediation: "Remove the unused variable.",
      complianceHits: [],
    },
    {
      filePath: "src/auth.js",
      line: 3,
      ruleId: "jwt-none",
      cwe: "CWE-327",
      severity: "MEDIUM",
      message: "JWT with 'none' algorithm",
      verdict: "UNCLEAR",
      confidence: 0.66,
      reasoning: "Needs more context.",
      remediation: "Review the JWT configuration.",
    },
  ],
};

describe("GuardrailReportRenderer", () => {
  let container;

  beforeEach(() => {
    document.body.innerHTML = '<div id="report"></div>';
    container = document.getElementById("report");
  });

  afterEach(() => {
    document.body.innerHTML = "";
  });

  test("exports the renderer class", () => {
    expect(typeof GuardrailReportRenderer).toBe("function");
  });

  test("renders summary metric cards", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);

    expect(container.textContent).toContain("Executive Summary");
    expect(container.textContent).toContain("Total");
    expect(container.textContent).toContain("High Priority");
    expect(container.textContent).toContain("False Positive");
    expect(container.textContent).toContain("Unclear");

    expect(container.querySelector('[data-metric="total"]').textContent).toBe("3");
    expect(container.querySelector('[data-metric="high"]').textContent).toBe("1");
    expect(container.querySelector('[data-metric="fp"]').textContent).toBe("1");
    expect(container.querySelector('[data-metric="unclear"]').textContent).toBe("1");
  });

  test("renders the findings table", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);

    const rows = container.querySelectorAll(".guardrail-table tbody tr");
    // 3 findings, each produces a row + a hidden detail row
    expect(rows.length).toBe(6);

    const visibleRows = Array.from(rows).filter((row) => row.style.display !== "none");
    expect(visibleRows.length).toBe(3);

    expect(container.textContent).toContain("no-eval");
    expect(container.textContent).toContain("unused-var");
    expect(container.textContent).toContain("jwt-none");
  });

  test("filters by verdict when a metric card is clicked", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);

    const highCard = container.querySelector('.metric-card[data-verdict="HIGH_PRIORITY"]');
    highCard.click();

    const visibleRows = container.querySelectorAll('.guardrail-table tbody tr:not([style*="none"])');
    expect(visibleRows.length).toBe(1);
    expect(container.textContent).toContain("no-eval");
    expect(container.textContent).not.toContain("unused-var");
  });

  test("filters by search input", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);

    const searchInput = container.querySelector('input[type="search"]');
    searchInput.value = "eval";
    searchInput.dispatchEvent(new Event("input"));

    const visibleRows = container.querySelectorAll('.guardrail-table tbody tr:not([style*="none"])');
    expect(visibleRows.length).toBe(1);
    expect(container.textContent).toContain("no-eval");
  });

  test("expands a row on click", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);

    const row = container.querySelector('.guardrail-table tbody tr[role="button"]');
    row.click();

    const detailRow = container.querySelector(".detail-row");
    expect(detailRow.style.display).toBe("table-row");
    expect(detailRow.textContent).toContain("Dangerous use of eval");
    expect(detailRow.textContent).toContain("Remove eval()");
  });

  test("sorts findings by confidence", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);

    const sortSelect = container.querySelector('select[id$="-sort"]');
    sortSelect.value = "confidence";
    sortSelect.dispatchEvent(new Event("change"));

    const rows = container.querySelectorAll('.guardrail-table tbody tr:not(.detail-row)');
    const firstRowText = rows[0].textContent;
    expect(firstRowText).toContain("no-eval");
  });

  test("sorts findings by location", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);

    const sortSelect = container.querySelector('select[id$="-sort"]');
    sortSelect.value = "location";
    sortSelect.dispatchEvent(new Event("change"));

    const rows = container.querySelectorAll('.guardrail-table tbody tr:not(.detail-row)');
    const firstRowText = rows[0].textContent;
    expect(firstRowText).toContain("src/app.js");
  });

  test("shows CI fail badge when high-priority findings exist", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);

    const badge = container.querySelector(".ci-verdict-badge");
    expect(badge.textContent).toBe("CI: Fail");
    expect(badge.classList.contains("ci-fail")).toBe(true);
  });

  test("shows CI pass badge when no high-priority findings exist", () => {
    const report = {
      summary: { total: 1, high_priority: 0, false_positive: 1, unclear: 0 },
      results: [
        {
          filePath: "src/clean.js",
          line: 1,
          ruleId: "style-rule",
          verdict: "FALSE_POSITIVE",
          confidence: 0.9,
        },
      ],
    };

    const renderer = new GuardrailReportRenderer(container);
    renderer.render(report);

    const badge = container.querySelector(".ci-verdict-badge");
    expect(badge.textContent).toBe("CI: Pass");
    expect(badge.classList.contains("ci-pass")).toBe(true);
  });

  test("destroy removes the dashboard", () => {
    const renderer = new GuardrailReportRenderer(container);
    renderer.render(sampleReport);
    expect(container.children.length).toBeGreaterThan(0);

    renderer.destroy();
    expect(container.children.length).toBe(0);
  });
});
