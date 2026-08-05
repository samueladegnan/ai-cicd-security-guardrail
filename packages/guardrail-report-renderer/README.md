# Guardrail Report Renderer

A reusable, dependency-light vanilla-JS component that turns a guardrail triage
report into an interactive dashboard: summary counts, Chart.js doughnut chart,
verdict filter, search, sortable findings table, and expandable rows with
reasoning, remediation, and code context.

## Installation

```bash
npm install guardrail-report-renderer
```

Or copy the two files directly:

```text
guardrail-report-renderer/src/index.js
guardrail-report-renderer/src/style.css
```

## Usage

```html
<link rel="stylesheet" href="path/to/style.css" />
<div id="report-container"></div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script src="path/to/index.js"></script>
<script>
  const renderer = new GuardrailReportRenderer('#report-container', {
    showChart: true,
    showToolbar: true,
    defaultSort: 'severity'
  });

  renderer.render(reportJson);
</script>
```

## Report schema

The renderer accepts the **raw guardrail JSON** produced by the CLI (results
with a nested `finding` object) or a flat/normalized shape.

```json
{
  "summary": {
    "total": 10,
    "high_priority": 2,
    "false_positive": 5,
    "unclear": 3
  },
  "results": [
    {
      "filePath": "src/app.js",
      "line": 42,
      "column": 5,
      "ruleId": "no-eval",
      "cwe": "CWE-94",
      "severity": "HIGH",
      "message": "Dangerous use of eval...",
      "verdict": "HIGH_PRIORITY",
      "confidence": 0.95,
      "reasoning": "...",
      "remediation": "...",
      "snippet": "eval(userInput);",
      "language": "javascript",
      "tool": "semgrep",
      "complianceHits": [
        { "framework": "cert_c", "ruleId": "ERR34-C", "title": "...", "description": "..." }
      ]
    }
  ]
}
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `showChart` | `boolean` | `true` | Render the verdict doughnut chart. |
| `showToolbar` | `boolean` | `true` | Show filter, search, and sort controls. |
| `defaultSort` | `string` | `"severity"` | Initial sort: `"severity"`, `"confidence"`, or `"location"`. |
| `onRowClick` | `function` | `null` | Called when a finding row is expanded. |
| `emptyMessage` | `string` | `"No findings match the current filters."` | Message shown when the table is empty. |
| `example` | `boolean` | `false` | Marks the rendered report as synthetic example data and changes provenance and CI wording accordingly. |

## API

- `render(report)`: render or update the dashboard with new report data
- `setVerdictFilter(verdict, toggle)`: programmatically filter by verdict
- `destroy()`: remove the dashboard and clean up the Chart.js instance

## Development

```bash
npm install
npm test
npm run build      # syncs src/ into the docs site
```

## License

MIT
