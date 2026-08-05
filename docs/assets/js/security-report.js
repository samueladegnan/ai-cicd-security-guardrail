/**
 * AI Guardrail security report page
 *
 * Shows scoped self-assessment results when available. Synthetic examples are
 * clearly labeled so they are never mistaken for repository findings.
 */
(function () {
  "use strict";

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

  function showExampleNotice(reason = "unavailable") {
    setDisplay("security-example-notice", "block")
    setDisplay("security-live-findings", "none")

    if (reason === "clean") {
      setDisplay("security-live-success", "block")
      setText("security-example-label", "Synthetic dashboard, scoped scan clean")
      setText("security-example-title", "Illustrative findings are shown below")
      setText(
        "security-example-copy",
        "The scoped self-assessment returned no findings in this repository's src/ tree. The dashboard below uses committed synthetic data to demonstrate the renderer. These examples are not repository issues."
      )
      setStatus("Scoped scan clean, synthetic dashboard", true)
    } else {
      setDisplay("security-live-success", "none")
      setText("security-example-label", "Synthetic dashboard, scan unavailable")
      setText("security-example-title", "Illustrative findings are shown below")
      setText(
        "security-example-copy",
        "The scoped self-assessment report is not available in this build. This page is showing committed synthetic data to demonstrate the dashboard. Every finding below is example data, not a repository issue."
      )
      setStatus("Synthetic example report", true)
    }
  }

  function showScopedFindings() {
    setDisplay("security-example-notice", "none")
    setDisplay("security-live-success", "none")
    setDisplay("security-live-findings", "block")
    setDisplay("security-empty", "none")
    setStatus("Scoped src/ self-assessment")
  }

  function showEmptyState(message = null) {
    setDisplay("security-example-notice", "none")
    setDisplay("security-live-success", "none")
    setDisplay("security-live-findings", "none")
    setDisplay("security-dashboard", "none")
    setDisplay("security-empty", "block")
    if (message) setText("security-empty-copy", message)
  }

  function showExampleFailureAfterCleanScan() {
    showEmptyState()
    setText("security-empty-title", "Scoped self-assessment is clean")
    setText(
      "security-empty-copy",
      "The scoped scan returned no findings, but the synthetic dashboard could not be loaded in this build. No example findings are being shown."
    )
    setStatus("Scoped scan clean, examples unavailable", true)
  }

  function showExampleFailureAfterUnavailableScan() {
    showEmptyState()
    setText("security-empty-title", "Security report unavailable")
    setText(
      "security-empty-copy",
      "The scoped self-assessment and synthetic dashboard could not be loaded in this build. Please retry after the next Pages build or explore the browser demo."
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
      defaultSort: "severity"
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

    if (hasLiveReport && liveReport.results.length > 0) {
      render(liveReport, false)
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
