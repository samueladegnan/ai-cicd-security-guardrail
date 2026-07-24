/**
 * AI-Driven CI/CD Security Guardrail — Interactive Browser Demo
 *
 * Runs entirely client-side. It parses SARIF, SonarQube JSON, or cppcheck XML
 * reports, maps CWEs to compliance controls, and uses a deterministic mock
 * classifier to triage findings just like the Python CLI.
 */

(function () {
  "use strict";

  const SAMPLES = {
    sarif: {
      label: "SARIF sample",
      data: JSON.stringify(
        {
          "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2-1-0.json",
          version: "2.1.0",
          runs: [
            {
              tool: {
                driver: {
                  name: "Demo SAST",
                  rules: [
                    {
                      id: "CWE-121",
                      name: "StackBasedBufferOverflow",
                      shortDescription: { text: "Stack-based buffer overflow" }
                    }
                  ]
                }
              },
              results: [
                {
                  ruleId: "CWE-121",
                  message: {
                    text: "Possible stack-based buffer overflow due to unchecked strcpy."
                  },
                  level: "error",
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: "sample_code/vulnerable.c" },
                        region: { startLine: 14, startColumn: 5 }
                      }
                    }
                  ]
                },
                {
                  ruleId: "unused-variable",
                  message: {
                    text: "Local variable 'result' is assigned but never used."
                  },
                  level: "note",
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: "sample_code/false_positive.c" },
                        region: { startLine: 13, startColumn: 9 }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        },
        null,
        2
      )
    },
    sonar: {
      label: "SonarQube JSON sample",
      data: JSON.stringify(
        {
          issues: [
            {
              rule: "c:S3519",
              severity: "BLOCKER",
              component: "sample_code/vulnerable.c",
              line: 14,
              message: "Possible stack-based buffer overflow due to unchecked strcpy.",
              cwes: ["CWE-121"]
            },
            {
              rule: "c:UnusedLocalVariable",
              severity: "MINOR",
              component: "sample_code/false_positive.c",
              line: 13,
              message: "Local variable 'result' is assigned but never used.",
              cwes: []
            }
          ]
        },
        null,
        2
      )
    },
    cppcheck: {
      label: "cppcheck XML sample",
      data: `<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck checkLevel="exhaustive">
    <error id="bufferAccessOutOfBounds" severity="error" msg="Buffer is accessed out of bounds." file0="sample_code/vulnerable.c" file="sample_code/vulnerable.c" line="14" cwe="119"/>
    <error id="unusedVariable" severity="style" msg="Unused variable: result" file0="sample_code/false_positive.c" file="sample_code/false_positive.c" line="13"/>
  </cppcheck>
</results>`
    }
  };

  const SOURCE_SNIPPETS = {
    "sample_code/vulnerable.c": [
      "void process_input(const char *input) {",
      "    char buffer[64];",
      "    /* Vulnerable to buffer overflow (CWE-121) */",
      "    strcpy(buffer, input);",
      "    printf(\"Processed: %s\\n\", buffer);",
      "}"
    ].join("\n"),
    "sample_code/false_positive.c": [
      "int calculate(int a, int b) {",
      "    /* Static analyzer might complain this variable is unused. */",
      "    int result = a + b;",
      "    return result;",
      "}"
    ].join("\n")
  };

  let complianceIndex = null;
  let complianceRules = null;

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  }

  function normalizeCwe(cwe) {
    if (!cwe) return "";
    let s = String(cwe).trim().toUpperCase();
    if (s.startsWith("CWE-")) return s;
    if (/^\d+$/.test(s)) return "CWE-" + s;
    return s;
  }

  function buildComplianceIndex(rules) {
    const index = new Map();
    for (const [framework, frameworkRules] of Object.entries(rules)) {
      for (const [ruleId, rule] of Object.entries(frameworkRules)) {
        for (const cwe of rule.cwes || []) {
          const key = normalizeCwe(cwe);
          if (!index.has(key)) index.set(key, []);
          index.get(key).push({ framework, ruleId, title: rule.title, description: rule.description });
        }
      }
    }
    return index;
  }

  function complianceHitsForCwe(cwe) {
    if (!complianceIndex) return [];
    return complianceIndex.get(normalizeCwe(cwe)) || [];
  }

  function parseReport(text, format) {
    if (format === "sarif" || (!format && text.trim().startsWith("{"))) {
      const data = JSON.parse(text);
      return parseSarif(data);
    }
    if (format === "sonar") {
      return parseSonar(JSON.parse(text));
    }
    if (format === "cppcheck") {
      return parseCppcheck(text);
    }
    // Best-effort auto detect
    const trimmed = text.trim();
    if (trimmed.startsWith("<")) return parseCppcheck(text);
    const data = JSON.parse(text);
    if (data.runs) return parseSarif(data);
    if (data.issues) return parseSonar(data);
    throw new Error("Could not determine report format.");
  }

  function parseSarif(data) {
    const findings = [];
    for (const run of data.runs || []) {
      const rules = {};
      for (const rule of run.tool?.driver?.rules || []) {
        rules[rule.id] = rule;
      }
      for (const result of run.results || []) {
        const physical = result.locations?.[0]?.physicalLocation || {};
        const region = physical.region || {};
        findings.push({
          ruleId: result.ruleId || "unknown",
          message: result.message?.text || "",
          filePath: physical.artifactLocation?.uri || "",
          line: region.startLine || 0,
          column: region.startColumn || 0,
          severity: result.level === "error" ? "HIGH" : result.level === "warning" ? "MEDIUM" : "LOW",
          cwe: result.ruleId?.startsWith("CWE-") ? result.ruleId : null,
          tool: "sarif",
          raw: result
        });
      }
    }
    return findings;
  }

  function parseSonar(data) {
    const findings = [];
    for (const issue of data.issues || []) {
      findings.push({
        ruleId: issue.rule || "unknown",
        message: issue.message || "",
        filePath: issue.component || "",
        line: issue.line || 0,
        column: 0,
        severity: issue.severity === "BLOCKER" ? "HIGH" : issue.severity === "CRITICAL" ? "HIGH" : issue.severity === "MAJOR" ? "MEDIUM" : "LOW",
        cwe: (issue.cwes?.[0]) ? normalizeCwe(issue.cwes[0]) : null,
        tool: "sonar",
        raw: issue
      });
    }
    return findings;
  }

  function parseCppcheck(xmlText) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlText, "application/xml");
    const findings = [];
    for (const error of doc.querySelectorAll("error")) {
      const file = error.getAttribute("file") || error.getAttribute("file0") || "";
      const cweAttr = error.getAttribute("cwe");
      findings.push({
        ruleId: error.getAttribute("id") || "unknown",
        message: error.getAttribute("msg") || "",
        filePath: file,
        line: parseInt(error.getAttribute("line") || "0", 10),
        column: 0,
        severity: error.getAttribute("severity") === "error" ? "HIGH" : error.getAttribute("severity") === "warning" ? "MEDIUM" : "LOW",
        cwe: cweAttr ? "CWE-" + cweAttr : null,
        tool: "cppcheck",
        raw: error
      });
    }
    return findings;
  }

  function inferCwe(finding) {
    if (finding.cwe) return finding.cwe;
    const text = (finding.ruleId + " " + finding.message).toUpperCase();
    if (text.includes("BUFFER") || text.includes("OVERFLOW") || text.includes("STRCPY") || text.includes("CWE-121")) return "CWE-121";
    if (text.includes("UNUSED")) return "CWE-563";
    return null;
  }

  function classifyFinding(finding) {
    const text = (finding.ruleId + " " + finding.message).toLowerCase();
    const cwe = normalizeCwe(finding.cwe);
    const memoryCwes = ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-131", "CWE-190", "CWE-415", "CWE-416", "CWE-590", "CWE-680", "CWE-787"];
    const fpWords = ["unused", "unreachable", "style", "dead store", "redundant", "informational", "cosmetic"];
    const highWords = ["overflow", "buffer", "strcpy", "memcpy", "stack", "heap", "use-after-free", "double free", "null terminator", "bounds", "out-of-bounds", "injection", "format string"];

    if (memoryCwes.includes(cwe) || highWords.some((w) => text.includes(w))) {
      return {
        verdict: "HIGH_PRIORITY",
        confidence: 0.93,
        reasoning: "The finding points to a memory-safety or security-sensitive code path that is likely exploitable.",
        remediation: "Replace unsafe calls with bounded alternatives (e.g., strncpy, snprintf), validate sizes, and run targeted tests."
      };
    }
    if (fpWords.some((w) => text.includes(w))) {
      return {
        verdict: "FALSE_POSITIVE",
        confidence: 0.88,
        reasoning: "The warning is stylistic or concerns an unused symbol; it does not represent a security risk.",
        remediation: "Remove the unused element or add an documented suppression if the code is intentional."
      };
    }
    return {
      verdict: "UNCLEAR",
      confidence: 0.64,
      reasoning: "There is not enough context to confidently triage this warning.",
      remediation: "Manually review the finding or provide additional context to the triage engine."
    };
  }

  function runTriage(findings) {
    const results = [];
    for (const finding of findings) {
      finding.cwe = inferCwe(finding);
      const hits = complianceHitsForCwe(finding.cwe);
      const classification = classifyFinding(finding);
      results.push({
        finding,
        complianceHits: hits,
        ...classification
      });
    }
    return results;
  }

  function getSnippet(filePath) {
    return SOURCE_SNIPPETS[filePath] || "";
  }

  function renderVerdictBadge(verdict) {
    const map = {
      HIGH_PRIORITY: ["High Priority", "verdict-high"],
      FALSE_POSITIVE: ["False Positive", "verdict-fp"],
      UNCLEAR: ["Unclear", "verdict-unclear"]
    };
    const [label, cls] = map[verdict] || [verdict, "verdict-unclear"];
    return `<span class="guardrail-badge ${cls}">${label}</span>`;
  }

  function renderComplianceHits(hits) {
    if (!hits.length) return "<em>None mapped</em>";
    return hits
      .map(
        (h) =>
          `<span class="guardrail-badge badge-control" title="${h.description}">${h.framework}: ${h.ruleId}</span>`
      )
      .join(" ");
  }

  function renderResults(results) {
    const summary = { total: results.length, high: 0, fp: 0, unclear: 0 };
    for (const r of results) {
      if (r.verdict === "HIGH_PRIORITY") summary.high++;
      else if (r.verdict === "FALSE_POSITIVE") summary.fp++;
      else summary.unclear++;
    }

    const summaryEl = document.getElementById("guardrail-summary");
    summaryEl.style.display = "block";
    summaryEl.innerHTML = `
      <div class="guardrail-grid">
        <div class="metric-card"><span class="metric-value">${summary.total}</span><span class="metric-label">Findings</span></div>
        <div class="metric-card metric-high"><span class="metric-value">${summary.high}</span><span class="metric-label">High Priority</span></div>
        <div class="metric-card metric-fp"><span class="metric-value">${summary.fp}</span><span class="metric-label">False Positives</span></div>
        <div class="metric-card metric-unclear"><span class="metric-value">${summary.unclear}</span><span class="metric-label">Unclear</span></div>
      </div>
      <div class="ci-verdict ${summary.high > 0 ? "ci-fail" : "ci-pass"}">
        <strong>CI Verdict:</strong> ${summary.high > 0 ? "Build would fail — high-priority risks remain." : "Build would pass — no high-priority risks."}
      </div>
    `;

    const tbody = document.getElementById("guardrail-results-body");
    tbody.innerHTML = "";
    if (results.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5"><em>No findings in this report.</em></td></tr>`;
      document.getElementById("guardrail-results").style.display = "block";
      return;
    }

    results.forEach((r, idx) => {
      const f = r.finding;
      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="finding-loc">${f.filePath || "—"}<br><small>line ${f.line || "—"}${f.column ? ":" + f.column : ""}</small></td>
        <td><code>${f.ruleId}</code><br><small class="cwe-label">${f.cwe || "—"}</small></td>
        <td>${renderComplianceHits(r.complianceHits)}</td>
        <td>${renderVerdictBadge(r.verdict)}</td>
        <td><div class="confidence-bar" style="--value:${Math.round(r.confidence * 100)}%"></div><small>${Math.round(r.confidence * 100)}%</small></td>
      `;
      const detailRow = document.createElement("tr");
      detailRow.className = "detail-row";
      const snippet = getSnippet(f.filePath);
      detailRow.innerHTML = `
        <td colspan="5">
          <div class="detail-content">
            <p><strong>Message:</strong> ${f.message || "—"}</p>
            <p><strong>Reasoning:</strong> ${r.reasoning}</p>
            <p><strong>Remediation:</strong> ${r.remediation}</p>
            ${snippet ? `<pre><code>${escapeHtml(snippet)}</code></pre>` : ""}
          </div>
        </td>
      `;
      detailRow.style.display = "none";
      row.addEventListener("click", () => {
        detailRow.style.display = detailRow.style.display === "none" ? "table-row" : "none";
      });
      row.style.cursor = "pointer";
      tbody.appendChild(row);
      tbody.appendChild(detailRow);
    });

    document.getElementById("guardrail-results").style.display = "block";
  }

  function escapeHtml(str) {
    return str.replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
  }

  function setStatus(msg, isError) {
    const el = document.getElementById("guardrail-status");
    el.textContent = msg;
    el.className = "guardrail-status" + (isError ? " status-error" : " status-info");
    el.style.display = msg ? "block" : "none";
  }

  ready(async () => {
    const input = document.getElementById("guardrail-input");
    const sampleSelect = document.getElementById("guardrail-sample");
    const runBtn = document.getElementById("guardrail-run");
    const resetBtn = document.getElementById("guardrail-reset");
    const formatSelect = document.getElementById("guardrail-format");

    // Load compliance rules
    try {
      const rulesUrl = window.GUARDRAIL_DEMO?.rulesUrl || "../data/compliance-rules.json";
      const res = await fetch(rulesUrl);
      if (!res.ok) throw new Error("Failed to load compliance rules");
      complianceRules = await res.json();
      complianceIndex = buildComplianceIndex(complianceRules);
    } catch (e) {
      console.error(e);
      setStatus("Could not load compliance rules; demo will run without compliance mapping.", true);
    }

    // Seed default sample
    input.value = SAMPLES.sarif.data;

    sampleSelect.addEventListener("change", () => {
      const key = sampleSelect.value;
      if (key && SAMPLES[key]) {
        input.value = SAMPLES[key].data;
        // Best-effort format sync
        formatSelect.value = key === "cppcheck" ? "cppcheck" : key === "sonar" ? "sonar" : "sarif";
      }
    });

    resetBtn.addEventListener("click", () => {
      sampleSelect.value = "";
      input.value = "";
      formatSelect.value = "auto";
      document.getElementById("guardrail-results").style.display = "none";
      document.getElementById("guardrail-summary").style.display = "none";
      setStatus("", false);
    });

    runBtn.addEventListener("click", async () => {
      setStatus("Running triage…", false);
      try {
        const format = formatSelect.value === "auto" ? undefined : formatSelect.value;
        const findings = parseReport(input.value, format);
        const results = runTriage(findings);
        renderResults(results);
        setStatus("Triage complete. Click any row to see reasoning, remediation, and code context.", false);
      } catch (err) {
        console.error(err);
        setStatus("Error: " + err.message, true);
      }
    });
  });
})();
