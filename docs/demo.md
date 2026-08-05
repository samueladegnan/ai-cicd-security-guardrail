---
layout: default
title: Demo | AI Guardrail
description: Inspect the AI Guardrail triage workflow with synthetic reports in your browser.
permalink: /demo/
wide: true
---

<div class="live-demo-page">
  <div class="demo-notice" role="note">
    <strong>Browser-only example.</strong> The bundled reports are synthetic. Custom files are parsed in your browser and are not uploaded or scanned by this site.
  </div>
  <div class="demo-dashboard">
    <section class="demo-panel demo-input-panel" aria-label="Input">
      <div class="guardrail-card input-card">
        <div class="input-intro">
          <h1 class="input-title">Try the triage workflow</h1>
          <p class="input-lead">Choose a sample report, upload a SAST file, or paste JSON or XML. The browser demo is a small client-side approximation of the parser and decision flow. It needs no API key.</p>
        </div>

        <div class="guardrail-controls">
          <div class="control-group">
            <label for="guardrail-sample">Sample report</label>
            <select id="guardrail-sample">
              <option value="">Custom input</option>
              <option value="sarif" selected>Synthetic SARIF, C and C++</option>
              <option value="brakeman">Synthetic Brakeman SARIF, Ruby</option>
              <option value="semgrep">Synthetic Semgrep SARIF, JavaScript</option>
              <option value="sonar">Synthetic SonarQube JSON</option>
              <option value="cppcheck">Synthetic cppcheck XML</option>
            </select>
          </div>
          <div class="control-group">
            <label for="guardrail-format">Format</label>
            <select id="guardrail-format">
              <option value="auto">Auto-detect</option>
              <option value="sarif">SARIF</option>
              <option value="sonar">SonarQube JSON</option>
              <option value="cppcheck">cppcheck XML</option>
            </select>
          </div>
        </div>

        <div id="drop-zone" class="drop-zone" role="button" tabindex="0" aria-label="Drag and drop a SAST report file here">
          <div class="drop-zone-content">
            <span class="drop-zone-icon" aria-hidden="true">↑</span>
            <p class="drop-zone-text"><strong>Drop a report here</strong> or click to browse</p>
            <p class="drop-zone-hint">Supports .sarif, .json, and .xml</p>
          </div>
        </div>

        <label for="guardrail-input" class="input-label">Raw report input</label>
        <textarea id="guardrail-input" class="guardrail-input" spellcheck="false" placeholder="Paste SARIF, SonarQube JSON, or cppcheck XML" aria-describedby="input-help input-source-note"></textarea>
        <p id="input-help" class="input-help">Selected examples show the exact report text below. You can edit it or replace it with your own report. Files stay in this browser tab.</p>
        <p id="input-source-note" class="input-source-note" role="status">Choose an example to load its raw SARIF, JSON, or XML input.</p>

        <div class="guardrail-actions">
          <button type="button" id="guardrail-run" class="btn-run"><span class="btn-icon" aria-hidden="true">▶</span><span class="btn-text">Run Triage</span></button>
          <button type="button" id="guardrail-reset" class="btn-reset">Reset</button>
          <button type="button" id="guardrail-export" class="btn-export" disabled>Export JSON</button>
        </div>

        <div id="guardrail-status" class="guardrail-status" role="status" aria-live="polite" style="display: none"></div>

        <div class="pipeline-card" aria-live="polite">
          <div class="pipeline-title">Workflow</div>
          <div class="pipeline-visual" aria-label="Pipeline stages">
            <div class="pipeline-group"><div class="pipeline-step" data-step="parse"><span class="pipeline-dot"></span><span class="pipeline-label">Parse</span></div><div class="pipeline-connector" aria-hidden="true"></div></div>
            <div class="pipeline-group"><div class="pipeline-step" data-step="context"><span class="pipeline-dot"></span><span class="pipeline-label">Context</span></div><div class="pipeline-connector" aria-hidden="true"></div></div>
            <div class="pipeline-group"><div class="pipeline-step" data-step="compliance"><span class="pipeline-dot"></span><span class="pipeline-label">Controls</span></div><div class="pipeline-connector" aria-hidden="true"></div></div>
            <div class="pipeline-group"><div class="pipeline-step" data-step="classify"><span class="pipeline-dot"></span><span class="pipeline-label">Decision</span></div><div class="pipeline-connector" aria-hidden="true"></div></div>
            <div class="pipeline-group"><div class="pipeline-step" data-step="report"><span class="pipeline-dot"></span><span class="pipeline-label">Report</span></div></div>
          </div>
          <p id="pipeline-status-text" class="pipeline-status-text">Ready. Choose a sample or add custom input.</p>
        </div>
      </div>
    </section>

    <section class="demo-panel demo-results-panel" aria-label="Results" id="results-section">
      <div id="guardrail-results-panel" style="display: none"></div>
      <div id="guardrail-empty-state" class="empty-state"><span class="empty-icon" aria-hidden="true">⌕</span><h2>No report yet</h2><p>Run a sample or add custom input to inspect the decision.</p></div>
    </section>
  </div>
</div>

<script>
  window.GUARDRAIL_DEMO = {
    rulesUrl: "{{ '/assets/data/compliance-rules.json' | relative_url }}",
    reportBaseUrl: "{{ '/assets/data/guardrail-reports/' | relative_url }}",
    sampleBaseUrl: "{{ '/assets/demo-samples/' | relative_url }}"
  };
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script src="{{ '/assets/js/guardrail-report-renderer.js' | relative_url }}"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-c.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-ruby.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
<script src="{{ '/assets/js/guardrail-demo.js' | relative_url }}"></script>
