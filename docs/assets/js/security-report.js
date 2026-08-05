/**
 * AI Guardrail security report page
 *
 * Shows scoped self-assessment results when available. Synthetic examples are
 * clearly labeled so they are never mistaken for repository findings.
 */
(function () {
  "use strict"

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn()
    } else {
      document.addEventListener("DOMContentLoaded", fn)
    }
  }

  function setDisplay(id, display) {
    const element = document.getElementById(id)
    if (element) element.style.display = display
  }

  function setText(id, text) {
    const element = document.getElementById(id)
    if (element) element.textContent = text
  }

  function setStatus(text, isExample = false) {
    const statusLabel = document.querySelector(".report-status-label")
    if (!statusLabel) return

    const dot = document.createElement("span")
    dot.className = isExample ? "status-dot status-dot--example" : "status-dot"
    dot.setAttribute("aria-hidden", "true")
    statusLabel.replaceChildren(dot, document.createTextNode(` ${text}`))
  }

  function normalizeReportPath(value) {
    const raw = String(value || "")
    if (/^[\\/]/.test(raw)) return ""

    let normalized = raw.replace(/\\/g, "/")
    while (normalized.startsWith("./")) {
      normalized = normalized.slice(2)
    }
    return normalized
  }

  function findingPath(result) {
    const finding = result && result.finding ? result.finding : result || {}
    return normalizeReportPath(finding.file_path || finding.filePath || result.file_path || result.filePath)
  }

  function isRealScopedFinding(result) {
    const path = findingPath(result)
    const segments = path.split("/")
    return path.startsWith("src/") && !segments.some((segment) =>
      !segment || segment === "." || segment === ".." || segment === "sample_code"
    )
  }

  function filterToScopedReport(report) {
    const results = report.results.filter(isRealScopedFinding)
    const summary = results.reduce(
      (counts, result) => {
        counts.total += 1
        if (result.verdict === "HIGH_PRIORITY") counts.high_priority += 1
        if (result.verdict === "FALSE_POSITIVE") counts.false_positive += 1
        if (result.verdict === "UNCLEAR") counts.unclear += 1
        return counts
      },
      { total: 0, high_priority: 0, false_positive: 0, unclear: 0 }
    )
    return { ...report, summary, results }
  }

  function showExampleNotice(reason = "unavailable") {
    setDisplay("security-example-notice", "block")
    setDisplay("security-live-findings", "none")

    if (reason === "clean") {
      setText("security-example-label", "No real issues found")
      setText(
        "security-example-inline-copy",
        "Example data is displayed because no real issues were found."
      )
      setText("security-example-title", "Example data is shown instead")
      setText(
        "security-example-copy",
        "The findings below are synthetic examples for inspecting the report interface, not repository issues."
      )
      setStatus("No real issues found, example data shown", true)
    } else {
      setText("security-example-label", "Scan unavailable")
      setText("security-example-inline-copy", "Example findings are shown for interface demonstration.")
      setText("security-example-title", "Example findings, not a live scan")
      setText(
        "security-example-copy",
        "The scoped self-assessment report is not available in this build, so this page cannot confirm whether the repository has findings. Every finding below is synthetic and not a repository issue."
      )
      setStatus("Scan unavailable, example findings", true)
    }
  }

  function showScopedFindings() {
    setDisplay("security-example-notice", "none")
    setDisplay("security-live-findings", "block")
    setDisplay("security-empty", "none")
    setStatus("Scoped src/ self-assessment")
  }

  function showEmptyState(message = null) {
    setDisplay("security-example-notice", "none")
    setDisplay("security-live-findings", "none")
    setDisplay("security-dashboard", "none")
    setDisplay("security-empty", "block")
    if (message) setText("security-empty-copy", message)
  }

  function showExampleFailureAfterCleanScan() {
    showEmptyState()
    setText("security-empty-title", "No real issues found")
    setText(
      "security-empty-copy",
      "The scoped scan found no real issues, but the example data could not be loaded in this build. No example findings are being shown."
    )
    setStatus("No real issues, example data unavailable", true)
  }

  function showExampleFailureAfterUnavailableScan() {
    showEmptyState()
    setText("security-empty-title", "Security report unavailable")
    setText(
      "security-empty-copy",
      "The scoped self-assessment and example data could not be loaded in this build. Please retry after the next Pages build or explore the browser demo."
    )
    setStatus("Security report unavailable", true)
  }

  function render(report, isExample, exampleReason = "unavailable") {
    const results = report && Array.isArray(report.results) ? report.results : null
    const dashboardElement = document.getElementById("security-dashboard")

    if (!results) {
      if (isExample && exampleReason === "clean") {
        showExampleFailureAfterCleanScan()
      } else {
        showExampleFailureAfterUnavailableScan()
      }
      return
    }

    setDisplay("security-empty", "none")
    if (isExample) {
      showExampleNotice(exampleReason)
    } else {
      showScopedFindings()
    }
    if (dashboardElement) dashboardElement.style.display = "block"

    const renderer = new GuardrailReportRenderer(dashboardElement, {
      showChart: true,
      showToolbar: true,
      defaultSort: "severity",
      example: isExample,
      exampleReason
    })

    renderer.render(report)
  }

  async function loadExampleReport() {
    const url = window.GUARDRAIL_EXAMPLE_REPORT_URL
    if (!url) return null

    const response = await fetch(url)
    if (!response.ok) throw new Error(`Synthetic report request failed: ${response.status}`)
    return response.json()
  }

  ready(async () => {
    const liveReport = window.GUARDRAIL_SECURITY_REPORT
    const hasLiveReport = liveReport && typeof liveReport === "object" && Array.isArray(liveReport.results)
    const scopedLiveReport = hasLiveReport ? filterToScopedReport(liveReport) : null
    const hasRealFindings = scopedLiveReport && scopedLiveReport.results.length > 0

    if (hasRealFindings) {
      render(scopedLiveReport, false)
      return
    }

    try {
      const exampleReport = await loadExampleReport()
      render(exampleReport, true, hasLiveReport ? "clean" : "unavailable")
    } catch (error) {
      console.error("Unable to load the synthetic security report", error)
      if (hasLiveReport) {
        showExampleFailureAfterCleanScan()
      } else {
        showExampleFailureAfterUnavailableScan()
      }
    }
  })
})()
