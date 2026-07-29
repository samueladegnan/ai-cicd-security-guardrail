---
layout: default
title: Live Demo
permalink: /demo/
wide: true
---

<div class="live-demo-page">
  <div class="demo-dashboard">
    <section class="demo-panel demo-input-panel" aria-label="Input">
      <div class="guardrail-card input-card">
        <div class="input-intro">
          <h2 class="input-title">🛡️ Live Demo</h2>
          <p class="input-lead">Select a sample report, upload a SAST file, or paste JSON/XML. The demo runs entirely in your browser.</p>
        </div>

        <div class="guardrail-controls">
          <div class="control-group">
            <label for="guardrail-sample">Sample report</label>
            <select id="guardrail-sample">
              <option value="">-- Custom input --</option>
              <option value="sarif" selected>SARIF sample (C/C++)</option>
              <option value="brakeman">Brakeman SARIF (Ruby)</option>
              <option value="semgrep">Semgrep SARIF (JavaScript)</option>
              <option value="sonar">SonarQube JSON sample</option>
              <option value="cppcheck">cppcheck XML sample</option>
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
          placeholder="Paste your SAST report here…"
          aria-describedby="input-help"
        ></textarea>
        <p id="input-help" class="input-help">
          Custom input is triaged client-side with the same deterministic classifier.
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
            <div class="pipeline-step" data-step="parse">
              <span class="pipeline-dot"></span>
              <span class="pipeline-label">Parse</span>
            </div>
            <div class="pipeline-connector" aria-hidden="true"></div>
            <div class="pipeline-step" data-step="context">
              <span class="pipeline-dot"></span>
              <span class="pipeline-label">Context</span>
            </div>
            <div class="pipeline-connector" aria-hidden="true"></div>
            <div class="pipeline-step" data-step="compliance">
              <span class="pipeline-dot"></span>
              <span class="pipeline-label">Compliance</span>
            </div>
            <div class="pipeline-connector" aria-hidden="true"></div>
            <div class="pipeline-step" data-step="classify">
              <span class="pipeline-dot"></span>
              <span class="pipeline-label">Classify</span>
            </div>
            <div class="pipeline-connector" aria-hidden="true"></div>
            <div class="pipeline-step" data-step="report">
              <span class="pipeline-dot"></span>
              <span class="pipeline-label">Report</span>
            </div>
          </div>
          <p id="pipeline-status-text" class="pipeline-status-text">Ready — select a sample and click Run to triage the report.</p>
        </div>
      </div>
    </section>

    <section class="demo-panel demo-results-panel" aria-label="Results" id="results-section">
      <div id="guardrail-summary" class="summary-card" style="display: none;">
        <div class="summary-header">
          <div>
            <h3 class="summary-title">Executive Summary</h3>
            <p class="summary-subtitle">Breakdown of triaged findings</p>
          </div>
          <div id="ci-verdict" class="ci-verdict-badge"></div>
        </div>
        <div class="summary-metrics">
          <div class="metric-card metric-total">
            <span class="metric-value" id="metric-total">0</span>
            <span class="metric-label">Total</span>
          </div>
          <div class="metric-card metric-high">
            <span class="metric-value" id="metric-high">0</span>
            <span class="metric-label">High Priority</span>
          </div>
          <div class="metric-card metric-fp">
            <span class="metric-value" id="metric-fp">0</span>
            <span class="metric-label">False Positive</span>
          </div>
          <div class="metric-card metric-unclear">
            <span class="metric-value" id="metric-unclear">0</span>
            <span class="metric-label">Unclear</span>
          </div>
        </div>
        <p class="chart-title">Verdict distribution</p>
        <div class="chart-wrap">
          <canvas id="verdict-chart" aria-label="Verdict distribution chart" role="img"></canvas>
        </div>
      </div>

      <div id="guardrail-empty-state" class="empty-state">
        <span class="empty-icon" aria-hidden="true">🔍</span>
        <h3>No report triaged yet</h3>
        <p>Select a sample report and click <strong>Run</strong> to see the triage results.</p>
      </div>

      <div id="guardrail-results" class="results-card" style="display: none;">
        <div class="results-toolbar">
          <div class="filter-group">
            <label for="filter-verdict" class="sr-only">Filter by verdict</label>
            <select id="filter-verdict">
              <option value="all">All verdicts</option>
              <option value="HIGH_PRIORITY">High Priority</option>
              <option value="FALSE_POSITIVE">False Positive</option>
              <option value="UNCLEAR">Unclear</option>
            </select>
          </div>
          <div class="search-group">
            <label for="search-findings" class="sr-only">Search findings</label>
            <input
              type="search"
              id="search-findings"
              placeholder="Search rule, CWE, file, or message…"
            />
          </div>
          <div class="sort-group">
            <label for="sort-findings" class="sr-only">Sort by</label>
            <select id="sort-findings">
              <option value="severity">Sort: Severity</option>
              <option value="confidence">Sort: Confidence</option>
              <option value="location">Sort: Location</option>
            </select>
          </div>
        </div>
        <p class="table-hint">Click any row to expand reasoning, remediation, and code context.</p>
        <div class="results-table-wrap">
          <table class="guardrail-table">
            <thead>
              <tr>
                <th scope="col">Location</th>
                <th scope="col">Rule / CWE</th>
                <th scope="col">Compliance</th>
                <th scope="col">Verdict</th>
                <th scope="col">Confidence</th>
              </tr>
            </thead>
            <tbody id="guardrail-results-body"></tbody>
          </table>
        </div>
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
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-c.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-ruby.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" />
<script src="{{ '/assets/js/guardrail-demo.js' | relative_url }}"></script>
