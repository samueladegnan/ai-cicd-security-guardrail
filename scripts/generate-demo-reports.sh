#!/usr/bin/env bash
# Regenerate the real guardrail reports used by the live demo.
# Run this whenever the guardrail pipeline or sample inputs change.
#
# Usage (Git Bash / WSL / macOS / Linux):
#   bash scripts/generate-demo-reports.sh

set -e

REPORTS_DIR="docs/assets/data/guardrail-reports"
SAMPLES_DIR="docs/assets/demo-samples"

mkdir -p "$REPORTS_DIR"

# Build the guardrail image if needed.
docker build -t ai-guardrail .

# Helper to run the guardrail CLI inside Docker with the repo mounted at /workspace.
run_guardrail() {
  local input_path=$1
  local format=$2
  local output_name=$3
  MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/workspace" ai-guardrail \
    "/workspace/$input_path" \
    --format "$format" \
    --provider mock \
    --output-json "/workspace/$REPORTS_DIR/$output_name.json" \
    --repo-root /workspace
}

run_guardrail "$SAMPLES_DIR/sample.sarif" sarif sarif
run_guardrail "$SAMPLES_DIR/brakeman.sarif" sarif brakeman
run_guardrail "$SAMPLES_DIR/semgrep.sarif" sarif semgrep
run_guardrail "$SAMPLES_DIR/sonar.json" sonarqube sonar
run_guardrail "$SAMPLES_DIR/cppcheck.xml" cppcheck cppcheck

echo "Demo reports regenerated in $REPORTS_DIR"
