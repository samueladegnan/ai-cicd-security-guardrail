---
layout: default
title: Security Report | AI Guardrail
description: Automated security self-assessment of the AI Guardrail repository.
permalink: /security/
wide: true
---

<div class="security-report-page">
  <div class="security-report-header">
    <div class="report-status-label"><span class="status-dot" aria-hidden="true"></span> Live <code>src/</code> self-assessment</div>
    <h1>Security Report</h1>
    <p class="security-report-lead">
      This page shows the latest report produced by running Bandit and Guardrail against this repository's <code>src/</code> tree. Results are published as part of the documentation build and should be treated as an automated review aid, not a substitute for engineering judgment.
    </p>
    <dl class="security-report-details">
      <div>
        <dt>Source scan</dt>
        <dd>Bandit SARIF generated from <code>src/</code></dd>
      </div>
      <div>
        <dt>Triage provider</dt>
        <dd>Deterministic mock provider; source stays in CI</dd>
      </div>
      <div>
        <dt>Report scope</dt>
        <dd>Repository <code>src/</code> tree only</dd>
      </div>
    </dl>
    <p class="security-report-meta security-report-timestamp">
      Published with the Pages build on {{ site.time | date: "%B %d, %Y at %H:%M %Z" }}.
    </p>
  </div>

  <div class="report-disclaimer" role="note">
    <strong>How to read this report:</strong> these are automated triage results, not a guarantee that the repository is vulnerability-free.
    Findings should be verified by an engineer before being accepted or dismissed.
  </div>

  <div id="security-live-success" class="live-scan-success" role="status" style="display: none;">
    <div class="live-scan-success__label">Live scan complete</div>
    <h2>The real Guardrail scan found no issues</h2>
    <p>
      The latest GitHub Actions self-assessment scanned this repository's <code>src/</code> tree and returned zero findings. To keep this page useful, the dashboard below uses clearly labeled example data. Those example findings are not issues in this repository.
    </p>
  </div>

  <div id="security-live-findings" class="live-scan-findings" role="status" style="display: none;">
    <div class="live-scan-findings__label">Live findings</div>
    <h2>Findings from the real Guardrail scan</h2>
    <p>
      The latest GitHub Actions self-assessment found findings in this repository's <code>src/</code> tree. The dashboard below shows those real scan results for review.
    </p>
  </div>

  <div id="security-example-notice" class="example-report-notice" role="status" style="display: none;">
    <div id="security-example-label" class="example-report-notice__label">Example report · live scan unavailable</div>
    <h2 id="security-example-title">Illustrative findings are shown below</h2>
    <p id="security-example-copy">
      The live CI report is not available in this build, so this page is showing a committed synthetic report to demonstrate the dashboard. Every finding below is sample data and is <strong>not a real issue in this repository</strong>.
    </p>
  </div>

  <div id="security-empty" class="empty-state" style="display: none;">
    <span class="empty-icon" aria-hidden="true">⏳</span>
    <h2 id="security-empty-title">Live report pending</h2>
    <p id="security-empty-copy">
      The latest CI report could not be loaded. The next Pages build will publish it. In the meantime, explore the
      <a href="{{ '/demo/' | relative_url }}">illustrative browser demo</a> with clearly labeled sample reports.
    </p>
  </div>

  <div id="security-dashboard" style="display: none;"></div>
</div>

<script>
  window.GUARDRAIL_SECURITY_REPORT = {{ site.data["guardrail-report"] | jsonify }};
  window.GUARDRAIL_EXAMPLE_REPORT_URL = "{{ '/assets/data/guardrail-reports/sarif.json' | relative_url }}";
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script src="{{ '/assets/js/guardrail-report-renderer.js' | relative_url }}"></script>
<script src="{{ '/assets/js/security-report.js' | relative_url }}"></script>
