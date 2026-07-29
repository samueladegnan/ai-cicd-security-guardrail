/**
 * AI-Driven CI/CD Security Guardrail — Security Report Page
 *
 * Loads the latest guardrail report embedded by Jekyll and renders it with the
 * shared GuardrailReportRenderer.
 */
(function () {
  "use strict";

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  }

  ready(() => {
    const report = window.GUARDRAIL_SECURITY_REPORT;
    const emptyEl = document.getElementById("security-empty");
    const dashboardEl = document.getElementById("security-dashboard");

    if (!report || !report.results || report.results.length === 0) {
      if (emptyEl) emptyEl.style.display = "block";
      if (dashboardEl) dashboardEl.style.display = "none";
      return;
    }

    if (emptyEl) emptyEl.style.display = "none";
    if (dashboardEl) dashboardEl.style.display = "block";

    const renderer = new GuardrailReportRenderer(dashboardEl, {
      showChart: true,
      showToolbar: true,
      defaultSort: "severity"
    });

    renderer.render(report);
  });
})();
