/**
 * AI-Driven CI/CD Security Guardrail - Interactive Browser Demo
 *
 * Sample reports are produced by the real guardrail Python pipeline (mock
 * provider) and committed as JSON. Custom input is still triaged client-side
 * with a deterministic fallback classifier.
 */

(function () {
  "use strict";

  const REPORT_KEYS = ["sarif", "brakeman", "semgrep", "sonar", "cppcheck"];

  const SAMPLES = {
    sarif: {
      label: "SARIF sample (C/C++)",
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
                    { id: "CWE-121", name: "StackBasedBufferOverflow", shortDescription: { text: "Stack-based buffer overflow" } },
                    { id: "unused-variable", shortDescription: { text: "Unused local variable" } },
                    { id: "CWE-457", shortDescription: { text: "Use of uninitialized variable" } },
                    { id: "missing-default-case", shortDescription: { text: "Missing default in switch" } },
                    { id: "CWE-415", shortDescription: { text: "Double free" } }
                  ]
                }
              },
              results: [
                {
                  ruleId: "CWE-121",
                  message: { text: "Possible stack-based buffer overflow due to unchecked strcpy." },
                  level: "error",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "sample_code/vulnerable.c" }, region: { startLine: 14, startColumn: 5 } } }]
                },
                {
                  ruleId: "unused-variable",
                  message: { text: "Local variable 'result' is assigned but never used." },
                  level: "note",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "sample_code/false_positive.c" }, region: { startLine: 13, startColumn: 9 } } }]
                },
                {
                  ruleId: "CWE-457",
                  message: { text: "Variable 'total' may be used before it is initialized." },
                  level: "warning",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "sample_code/vulnerable.c" }, region: { startLine: 22, startColumn: 10 } } }]
                },
                {
                  ruleId: "missing-default-case",
                  message: { text: "Switch statement does not have a default case." },
                  level: "note",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "sample_code/vulnerable.c" }, region: { startLine: 35, startColumn: 5 } } }]
                },
                {
                  ruleId: "CWE-415",
                  message: { text: "Memory is freed more than once." },
                  level: "error",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "sample_code/vulnerable.c" }, region: { startLine: 41, startColumn: 5 } } }]
                }
              ]
            }
          ]
        },
        null,
        2
      )
    },
    brakeman: {
      label: "Brakeman SARIF (Ruby)",
      data: JSON.stringify(
        {
          version: "2.1.0",
          runs: [
            {
              tool: {
                driver: {
                  name: "Brakeman",
                  language: "ruby",
                  rules: [
                    { id: "SQL Injection", shortDescription: { text: "Possible SQL injection" } },
                    { id: "Unused Method", shortDescription: { text: "Method never called" } },
                    { id: "Weak Hash", shortDescription: { text: "Weak hash algorithm" } },
                    { id: "Unscoped Query", shortDescription: { text: "Unscoped ActiveRecord query" } },
                    { id: "Missing Authorization", shortDescription: { text: "No authorization check" } }
                  ]
                }
              },
              results: [
                {
                  ruleId: "SQL Injection",
                  message: { text: "Possible SQL injection in User.find_by_sql call." },
                  level: "error",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "app/models/user.rb" }, region: { startLine: 42, startColumn: 5 } } }]
                },
                {
                  ruleId: "Unused Method",
                  message: { text: "Method admin? is never used." },
                  level: "note",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "app/controllers/admin_controller.rb" }, region: { startLine: 12, startColumn: 3 } } }]
                },
                {
                  ruleId: "Weak Hash",
                  message: { text: "MD5 used for password digest." },
                  level: "warning",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "app/models/user.rb" }, region: { startLine: 18, startColumn: 10 } } }]
                },
                {
                  ruleId: "Unscoped Query",
                  message: { text: "Unscoped ActiveRecord query may leak records across tenants." },
                  level: "warning",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "app/controllers/posts_controller.rb" }, region: { startLine: 7, startColumn: 15 } } }]
                },
                {
                  ruleId: "Missing Authorization",
                  message: { text: "No authorization check before destroying a record." },
                  level: "error",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "app/controllers/admin_controller.rb" }, region: { startLine: 28, startColumn: 3 } } }]
                }
              ]
            }
          ]
        },
        null,
        2
      )
    },
    semgrep: {
      label: "Semgrep SARIF (JavaScript)",
      data: JSON.stringify(
        {
          version: "2.1.0",
          runs: [
            {
              tool: {
                driver: {
                  name: "Semgrep",
                  language: "javascript",
                  rules: [
                    { id: "jwt-none-alg", shortDescription: { text: "JWT none algorithm" } },
                    { id: "no-eval", shortDescription: { text: "Dangerous use of eval" } },
                    { id: "hardcoded-secret", shortDescription: { text: "Hardcoded credential" } },
                    { id: "regex-dos", shortDescription: { text: "Regular expression denial of service" } },
                    { id: "insecure-random", shortDescription: { text: "Predictable random value" } }
                  ]
                }
              },
              results: [
                {
                  ruleId: "jwt-none-alg",
                  message: { text: "Insecure JWT algorithm 'none' used." },
                  level: "error",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "src/auth.js" }, region: { startLine: 23, startColumn: 10 } } }]
                },
                {
                  ruleId: "no-eval",
                  message: { text: "Use of eval can lead to code injection." },
                  level: "error",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "src/utils.js" }, region: { startLine: 8, startColumn: 15 } } }]
                },
                {
                  ruleId: "hardcoded-secret",
                  message: { text: "Hardcoded API key detected." },
                  level: "error",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "src/config.js" }, region: { startLine: 5, startColumn: 20 } } }]
                },
                {
                  ruleId: "regex-dos",
                  message: { text: "User input reaches a regular expression with potential exponential time." },
                  level: "warning",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "src/validation.js" }, region: { startLine: 31, startColumn: 22 } } }]
                },
                {
                  ruleId: "insecure-random",
                  message: { text: "Math.random() used for security-sensitive value." },
                  level: "warning",
                  locations: [{ physicalLocation: { artifactLocation: { uri: "src/tokens.js" }, region: { startLine: 14, startColumn: 18 } } }]
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
            },
            {
              rule: "c:UninitializedVariable",
              severity: "MAJOR",
              component: "sample_code/vulnerable.c",
              line: 22,
              message: "Variable 'total' may be used before it is initialized.",
              cwes: ["CWE-457"]
            },
            {
              rule: "c:MissingDefaultInSwitch",
              severity: "MINOR",
              component: "sample_code/vulnerable.c",
              line: 35,
              message: "Switch statement does not have a default case.",
              cwes: []
            },
            {
              rule: "cpp:S5025",
              severity: "BLOCKER",
              component: "sample_code/vulnerable.c",
              line: 41,
              message: "Memory is freed more than once.",
              cwes: ["CWE-415"]
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
  <errors>
    <error id="bufferAccessOutOfBounds" severity="error" msg="Buffer is accessed out of bounds." cwe="119">
      <location file="sample_code/vulnerable.c" line="14" column="5"/>
    </error>
    <error id="uninitvar" severity="error" msg="Variable 'total' is not initialized." cwe="457">
      <location file="sample_code/vulnerable.c" line="22" column="10"/>
    </error>
    <error id="doubleFree" severity="error" msg="Memory is freed more than once." cwe="415">
      <location file="sample_code/vulnerable.c" line="41" column="5"/>
    </error>
    <error id="unusedVariable" severity="style" msg="Unused variable: result">
      <location file="sample_code/false_positive.c" line="13" column="9"/>
    </error>
    <error id="missingDefaultCase" severity="style" msg="Switch statement does not have a default case.">
      <location file="sample_code/vulnerable.c" line="35" column="5"/>
    </error>
  </errors>
</results>`
    }
  };

  let complianceIndex = null;
  let complianceRules = null;
  let reportBaseUrl = "";
  let renderer = null;

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
      return parseSarif(JSON.parse(text));
    }
    if (format === "sonar") {
      return parseSonar(JSON.parse(text));
    }
    if (format === "cppcheck") {
      return parseCppcheck(text);
    }
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
      const location = error.querySelector("location");
      const file = location?.getAttribute("file") || "";
      const cweAttr = error.getAttribute("cwe");
      findings.push({
        ruleId: error.getAttribute("id") || "unknown",
        message: error.getAttribute("msg") || "",
        filePath: file,
        line: parseInt(location?.getAttribute("line") || "0", 10),
        column: parseInt(location?.getAttribute("column") || "0", 10),
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
    if (text.includes("SQL") || text.includes("INJECTION")) return "CWE-89";
    if (text.includes("EVAL")) return "CWE-94";
    if (text.includes("JWT") || text.includes("CRYPTO")) return "CWE-327";
    if (text.includes("UNUSED")) return "CWE-563";
    if (text.includes("DOUBLE") || text.includes("FREE")) return "CWE-415";
    if (text.includes("UNINIT")) return "CWE-457";
    if (text.includes("HARDCODED") || text.includes("SECRET")) return "CWE-798";
    if (text.includes("REGEX") || text.includes("REDOS")) return "CWE-1333";
    if (text.includes("RANDOM")) return "CWE-338";
    return null;
  }

  function classifyFinding(finding) {
    const text = (finding.ruleId + " " + finding.message).toLowerCase();
    const cwe = normalizeCwe(finding.cwe);
    const memoryCwes = ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-131", "CWE-190", "CWE-415", "CWE-416", "CWE-590", "CWE-680", "CWE-787"];
    const webCwes = ["CWE-79", "CWE-89", "CWE-94", "CWE-327", "CWE-798"];
    const fpWords = ["unused", "unreachable", "style", "dead store", "redundant", "informational", "cosmetic"];
    const highWords = ["overflow", "buffer", "strcpy", "memcpy", "stack", "heap", "use-after-free", "double free", "null terminator", "bounds", "out-of-bounds", "injection", "format string", "sql", "eval", "jwt", "hardcoded", "secret", "md5", "weak", "hash", "unauthorized", "unscoped", "authorization", "uninitialized"];
    const unclearWords = ["missing", "default"];

    if (memoryCwes.includes(cwe) || webCwes.includes(cwe) || highWords.some((w) => text.includes(w))) {
      return {
        verdict: "HIGH_PRIORITY",
        confidence: 0.93,
        reasoning: "The finding matches a memory-safety or injection-style rule and is likely exploitable.",
        remediation: "Replace unsafe calls with bounded alternatives, validate input sizes, and add targeted tests before closing."
      };
    }
    if (fpWords.some((w) => text.includes(w))) {
      return {
        verdict: "FALSE_POSITIVE",
        confidence: 0.88,
        reasoning: "The warning is stylistic or refers to an unused symbol; it does not present a security risk.",
        remediation: "Remove the unused element or add a documented suppression if the code is intentional."
      };
    }
    if (unclearWords.some((w) => text.includes(w))) {
      return {
        verdict: "UNCLEAR",
        confidence: 0.66,
        reasoning: "The warning could indicate a real issue, but the available context is insufficient for a confident verdict.",
        remediation: "Manually review the finding and add context or a documented suppression once the intent is confirmed."
      };
    }
    return {
      verdict: "UNCLEAR",
      confidence: 0.64,
      reasoning: "The available context is insufficient to confidently triage this warning.",
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

  function severityRank(severity) {
    const map = { HIGH: 3, MEDIUM: 2, LOW: 1 };
    return map[severity] || 0;
  }

  function setStatus(msg, isError) {
    const el = document.getElementById("guardrail-status");
    el.textContent = msg;
    el.className = "guardrail-status" + (isError ? " status-error" : " status-info");
    el.style.display = msg ? "block" : "none";
  }

  function setPipelineStep(step, label) {
    document.querySelectorAll(".pipeline-step").forEach((el) => {
      el.classList.remove("active", "complete");
      const s = el.dataset.step;
      const order = { parse: 0, context: 1, compliance: 2, classify: 3, report: 4 };
      if (order[s] < order[step]) el.classList.add("complete");
      if (s === step) el.classList.add("active");
    });
    if (label) {
      const statusText = document.getElementById("pipeline-status-text");
      if (statusText) statusText.textContent = label;
    }
  }

  function resetPipeline() {
    document.querySelectorAll(".pipeline-step").forEach((el) => el.classList.remove("active", "complete"));
    const statusText = document.getElementById("pipeline-status-text");
    if (statusText) statusText.textContent = "Ready — click Run to start the triage pipeline.";
  }

  function normalizeResults(results) {
    return {
      summary: {
        total: results.length,
        high_priority: results.filter((r) => r.verdict === "HIGH_PRIORITY").length,
        false_positive: results.filter((r) => r.verdict === "FALSE_POSITIVE").length,
        unclear: results.filter((r) => r.verdict === "UNCLEAR").length
      },
      results: results.map((r) => ({
        finding: r.finding,
        verdict: r.verdict,
        confidence: r.confidence,
        reasoning: r.reasoning,
        remediation: r.remediation,
        compliance_hits: r.complianceHits || r.compliance_hits || []
      }))
    };
  }

  function renderResultsPanel(report) {
    const panel = document.getElementById("guardrail-results-panel");
    const emptyState = document.getElementById("guardrail-empty-state");
    if (emptyState) emptyState.style.display = "none";
    panel.style.display = "block";

    if (!renderer) {
      renderer = new GuardrailReportRenderer(panel, {
        showChart: true,
        showToolbar: true,
        defaultSort: "severity"
      });
    }

    renderer.render(report);
  }

  function renderClientResults(results) {
    const report = normalizeResults(results);
    renderResultsPanel(report);
  }

  function renderReport(report) {
    renderResultsPanel(report);
  }

  function reportUrl(key) {
    return `${reportBaseUrl}${key}.json`;
  }

  function isSampleReport(key) {
    return key && REPORT_KEYS.includes(key);
  }

  async function runPipeline(key, text, format) {
    const steps = [
      { step: "parse", label: "Parsing report…", delay: 400 },
      { step: "context", label: "Extracting code context…", delay: 400 },
      { step: "compliance", label: "Mapping compliance controls…", delay: 400 },
      { step: "classify", label: "Classifying findings…", delay: 500 },
      { step: "report", label: "Building report…", delay: 200 }
    ];

    for (const s of steps) {
      setPipelineStep(s.step, s.label);
      setStatus(s.label, false);
      await new Promise((resolve) => setTimeout(resolve, s.delay));
    }

    setPipelineStep("report", "Triage complete.");

    if (isSampleReport(key)) {
      const res = await fetch(reportUrl(key));
      if (!res.ok) throw new Error("Failed to load real report for " + key);
      const report = await res.json();
      renderReport(report);
      setStatus("Triage complete. Sample reports are produced by the guardrail CLI.", false);
      return;
    }

    const resolvedFormat = format || (text.trim().startsWith("<") ? "cppcheck" : undefined);
    const findings = parseReport(text, resolvedFormat);
    const results = runTriage(findings);
    renderClientResults(results);
    setStatus("Triage complete. Click any row for details.", false);
  }

  function exportReport() {
    if (!renderer || !renderer.report) return;
    const exported = {
      ...(renderer._originalReport || { summary: renderer.report.summary, results: renderer.report.results }),
      exported_at: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "guardrail-report.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function handleFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const input = document.getElementById("guardrail-input");
      input.value = e.target.result;
      const name = file.name.toLowerCase();
      const formatSelect = document.getElementById("guardrail-format");
      if (name.endsWith(".xml")) formatSelect.value = "cppcheck";
      else if (name.endsWith(".json") && input.value.includes("\"issues\"")) formatSelect.value = "sonar";
      else formatSelect.value = "auto";
      setStatus(`Loaded ${file.name}. Click Run AI Guardrail to triage.`, false);
    };
    reader.readAsText(file);
  }

  ready(async () => {
    const input = document.getElementById("guardrail-input");
    const sampleSelect = document.getElementById("guardrail-sample");
    const runBtn = document.getElementById("guardrail-run");
    const resetBtn = document.getElementById("guardrail-reset");
    const exportBtn = document.getElementById("guardrail-export");
    const formatSelect = document.getElementById("guardrail-format");
    const dropZone = document.getElementById("drop-zone");
    reportBaseUrl = window.GUARDRAIL_DEMO?.reportBaseUrl || "";

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

    input.value = SAMPLES.sarif.data;

    sampleSelect.addEventListener("change", () => {
      const key = sampleSelect.value;
      if (key && SAMPLES[key]) {
        input.value = SAMPLES[key].data;
        formatSelect.value = key === "cppcheck" ? "cppcheck" : key === "sonar" ? "sonar" : "sarif";
      }
    });

    resetBtn.addEventListener("click", () => {
      sampleSelect.value = "";
      input.value = "";
      formatSelect.value = "auto";
      if (renderer) {
        renderer.destroy();
        renderer = null;
      }
      const panel = document.getElementById("guardrail-results-panel");
      const emptyState = document.getElementById("guardrail-empty-state");
      if (panel) panel.style.display = "none";
      if (emptyState) emptyState.style.display = "block";
      document.getElementById("guardrail-export").disabled = true;
      setStatus("", false);
      resetPipeline();
      const statusText = document.getElementById("pipeline-status-text");
      if (statusText) statusText.textContent = "Ready — click Run to start the triage pipeline.";
    });

    runBtn.addEventListener("click", async () => {
      runBtn.disabled = true;
      setStatus("Initializing pipeline…", false);
      try {
        const key = sampleSelect.value;
        const format = formatSelect.value === "auto" ? undefined : formatSelect.value;
        await runPipeline(key, input.value, format);
      } catch (err) {
        console.error(err);
        setStatus("Error: " + err.message, true);
        resetPipeline();
      } finally {
        runBtn.disabled = false;
      }
    });

    exportBtn.addEventListener("click", exportReport);

    ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
      }, false);
    });

    ["dragenter", "dragover"].forEach((eventName) => {
      dropZone.addEventListener(eventName, () => dropZone.classList.add("drop-zone-active"), false);
    });

    ["dragleave", "drop"].forEach((eventName) => {
      dropZone.addEventListener(eventName, () => dropZone.classList.remove("drop-zone-active"), false);
    });

    dropZone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files[0];
      handleFile(file);
    }, false);

    const fileInput = document.createElement("input");
    fileInput.type = "file";
    fileInput.accept = ".sarif,.json,.xml";
    fileInput.style.display = "none";
    fileInput.addEventListener("change", (e) => {
      const target = e.target;
      if (target.files && target.files[0]) {
        handleFile(target.files[0]);
      }
      target.value = "";
    });
    document.body.appendChild(fileInput);

    function openFilePicker() {
      fileInput.value = "";
      fileInput.click();
    }

    dropZone.addEventListener("click", openFilePicker);
    dropZone.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openFilePicker();
      }
    });
  });
})();
