---
layout: default
title: Live Demo
permalink: /app/
---

<div class="live-demo-page">
  <p class="lead">
    Paste a SARIF, SonarQube JSON, or cppcheck XML report and watch the guardrail
    triage it in your browser — no backend, no API key.
  </p>

  <div class="guardrail-card">
    <div class="guardrail-controls">
      <div class="control-group">
        <label for="guardrail-sample">Choose a sample report</label>
        <select id="guardrail-sample">
          <option value="">— Custom input —</option>
          <option value="sarif" selected>SARIF sample (2 findings)</option>
          <option value="sonar">SonarQube JSON sample (2 findings)</option>
          <option value="cppcheck">cppcheck XML sample (2 findings)</option>
        </select>
      </div>
      <div class="control-group">
        <label for="guardrail-format">Report format</label>
        <select id="guardrail-format">
          <option value="auto">Auto-detect</option>
          <option value="sarif">SARIF</option>
          <option value="sonar">SonarQube JSON</option>
          <option value="cppcheck">cppcheck XML</option>
        </select>
      </div>
    </div>

    <label for="guardrail-input" class="input-label">Report input</label>
    <textarea id="guardrail-input" class="guardrail-input" spellcheck="false" placeholder="Paste your SAST report here…"></textarea>

    <div class="guardrail-actions">
      <button id="guardrail-run" class="btn-run">Run AI Guardrail</button>
      <button id="guardrail-reset" class="btn-reset">Reset</button>
    </div>

    <div id="guardrail-status" class="guardrail-status" style="display: none;"></div>
  </div>

  <div id="guardrail-summary" class="guardrail-card" style="display: none;"></div>

  <div id="guardrail-results" class="guardrail-card" style="display: none;">
    <h3>Detailed Findings</h3>
    <p class="table-hint">Click any row to expand reasoning, remediation, and code context.</p>
    <div class="results-table-wrap">
      <table class="guardrail-table">
        <thead>
          <tr>
            <th>Location</th>
            <th>Rule / CWE</th>
            <th>Compliance Controls</th>
            <th>Verdict</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody id="guardrail-results-body"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
  window.GUARDRAIL_DEMO = {
    rulesUrl: "{{ '/assets/data/compliance-rules.json' | relative_url }}"
  };
</script>
<script src="{{ '/assets/js/guardrail-demo.js' | relative_url }}"></script>
