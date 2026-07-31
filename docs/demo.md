---
layout: default
title: Live Demo | AI Guardrail
description: Try the AI Guardrail report triage dashboard with synthetic sample findings in your browser.
permalink: /demo/
wide: true
---

<div class="live-demo-page">
  <div class="demo-notice" role="note">
    <strong>Illustrative demo data.</strong> The reports below are synthetic examples designed to show the dashboard and triage flow. They are not findings from the AI Guardrail repository or from your device.
  </div>
  <div class="demo-dashboard">
    <section class="demo-panel demo-input-panel" aria-label="Input">
      <div class="guardrail-card input-card">
        <div class="input-intro">
          <h1 class="input-title">🛡️ Try the triage workflow</h1>
          <p class="input-lead">Choose an illustrative report, upload a SAST file, or paste JSON/XML. Custom input is parsed and triaged entirely in your browser.</p>
        </div>

        <div class="guardrail-controls">
          <div class="control-group">
            <label for="guardrail-sample">Illustrative report</label>
            <select id="guardrail-sample">
              <option value="">-- Custom input --</option>
              <option value="sarif" selected>Synthetic SARIF (C/C++)</option>
              <option value="brakeman">Synthetic Brakeman SARIF (Ruby)</option>
              <option value="semgrep">Synthetic Semgrep SARIF (JavaScript)</option>
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

        <div
          id="drop-zone"
          class="drop-zone"
          role="button"
          tabindex="0"
          aria-label="Drag and drop a SAST report file here"
        >
          <div class="drop-zone-content">
            <span class="drop-zone-icon" aria-hidden="true">⬆️</span>
            <p class="drop-zone-text">
              <strong>Drag &amp; drop</strong> a SARIF, SonarQube, or cppcheck file
            </p>
            <p class="drop-zone-hint">or click to browse — supports .sarif, .json, .xml</p>
          </div>
        </div>

        <label for="guardrail-input" class="input-label">Or paste report JSON/XML</label>
        <textarea
          id="guardrail-input"
          class="guardrail-input"
          spellcheck="false"
          placeholder="Paste a SAST report here…"
          aria-describedby="input-help"
        ></textarea>
        <p id="input-help" class="input-help">
          Custom input is triaged client-side with the same deterministic classifier used for the demo. Empty input is rejected before the pipeline starts.
        </p>

        <div class="guardrail-actions">
          <button id="guardrail-run" class="btn-run">
            <span class="btn-icon" aria-hidden="true">▶</span>
            <span class="btn-text">Run Triage</span>
          </button>
          <button id="guardrail-reset" class="btn-reset">Reset</button>
          <button id="guardrail-export" class="btn-export" disabled>Export JSON</button>
        </div>

        <div id="guardrail-status" class="guardrail-status" style="display: none;"></div>

        <div class="pipeline-card" aria-live="polite">
          <div class="pipeline-title">Pipeline status</div>
          <div class="pipeline-visual" aria-label="Pipeline stages">
            <div class="pipeline-group">
              <div class="pipeline-step" data-step="parse"><span class="pipeline-dot"></span><span class="pipeline-label">Parse</span></div>
              <div class="pipeline-connector" aria-hidden="true"></div>
            </div>
            <div class="pipeline-group">
              <div class="pipeline-step" data-step="context"><span class="pipeline-dot"></span><span class="pipeline-label">Context</span></div>
              <div class="pipeline-connector" aria-hidden="true"></div>
            </div>
            <div class="pipeline-group">
              <div class="pipeline-step" data-step="compliance"><span class="pipeline-dot"></span><span class="pipeline-label">Compliance</span></div>
              <div class="pipeline-connector" aria-hidden="true"></div>
            </div>
            <div class="pipeline-group">
              <div class="pipeline-step" data-step="classify"><span class="pipeline-dot"></span><span class="pipeline-label">Classify</span></div>
              <div class="pipeline-connector" aria-hidden="true"></div>
            </div>
            <div class="pipeline-group">
              <div class="pipeline-step" data-step="report"><span class="pipeline-dot"></span><span class="pipeline-label">Report</span></div>
            </div>
          </div>
          <p id="pipeline-status-text" class="pipeline-status-text">Ready — select an illustrative report and click Run to triage it.</p>
        </div>
      </div>
    </section>

    <section class="demo-panel demo-results-panel" aria-label="Results" id="results-section">
      <div id="guardrail-results-panel" style="display: none;"></div>
      <div id="guardrail-empty-state" class="empty-state">
        <span class="empty-icon" aria-hidden="true">🔍</span>
        <h2>No report triaged yet</h2>
        <p>Select an illustrative report and click <strong>Run</strong> to see the dashboard.</p>
      </div>
    </section>
  </div>
</div>

<script>
  window.GUARDRAIL_DEMO = {
    rulesUrl: "{{ '/assets/data/compliance-rules.json' | relative_url }}",
    reportBaseUrl: "{{ '/assets/data/guardrail-reports/' | relative_url }}"
  };
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script src="{{ '/assets/js/guardrail-report-renderer.js' | relative_url }}"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-c.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-ruby.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" />
<script src="{{ '/assets/js/guardrail-demo.js' | relative_url }}"></script>
