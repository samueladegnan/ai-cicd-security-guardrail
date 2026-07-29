---
layout: default
title: Security Report
permalink: /security/
wide: true
---

<div class="security-report-page">
  <div class="security-report-header">
    <p class="security-report-meta">
      Generated automatically by the
      <a href="{{ site.repository_url }}/blob/main/.github/workflows/guardrail.yml" target="_blank" rel="noopener noreferrer">
        ai-cicd-security-guardrail GitHub Actions workflow
      </a>.
    </p>
    <p class="security-report-meta">
      Generated with <strong>ai-cicd-security-guardrail</strong>, the current project.
    </p>
    <p class="security-report-meta security-report-timestamp">
      Last generated: {{ site.time | date: "%B %d, %Y at %H:%M %Z" }}
    </p>
  </div>

  <div id="security-empty" class="empty-state" style="display: block;">
    <span class="empty-icon" aria-hidden="true">⏳</span>
    <h3>Latest report not yet available</h3>
    <p>
      The latest guardrail report will appear here once the CI pipeline produces it.
      You can also explore the <a href="{{ '/demo/' | relative_url }}">live demo</a> with sample reports.
    </p>
  </div>

  <div id="security-dashboard" style="display: none;"></div>
</div>

<script>
  window.GUARDRAIL_SECURITY_REPORT = {{ site.data["guardrail-report"] | jsonify }};
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script src="{{ '/assets/js/guardrail-report-renderer.js' | relative_url }}"></script>
<script src="{{ '/assets/js/security-report.js' | relative_url }}"></script>
