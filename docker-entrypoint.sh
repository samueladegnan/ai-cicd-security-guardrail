#!/bin/sh
set -eu

# GitHub exposes action inputs as INPUT_* environment variables. Input names
# containing hyphens have varied across runner versions, so accept both forms.
input_value() {
  raw_name=$1
  normalized_name=$(printf '%s' "$raw_name" | tr '[:lower:]-' '[:upper:]_')
  value=$(printenv "INPUT_${normalized_name}" 2>/dev/null || true)
  if [ -z "$value" ]; then
    value=$(printenv "INPUT_${raw_name}" 2>/dev/null || true)
  fi
  printf '%s' "$value"
}

export_if_set() {
  env_name=$1
  input_name=$2
  value=$(input_value "$input_name")
  if [ -n "$value" ]; then
    export "${env_name}=${value}"
  fi
}

# Keep API keys and other settings in the environment rather than adding them
# to the process command line, where they can appear in diagnostics.
export_if_set GUARDRAIL_LLM_PROVIDER provider
export_if_set GUARDRAIL_LLM_API_KEY llm-api-key
export_if_set GUARDRAIL_LLM_MODEL llm-model
export_if_set GUARDRAIL_FALLBACK_PROVIDERS fallback-providers
export_if_set GUARDRAIL_MAX_CONCURRENCY max-concurrency
export_if_set GUARDRAIL_FAIL_ON_UNCLEAR fail-on-unclear
export_if_set GUARDRAIL_CACHE_BACKEND cache-backend
export_if_set GUARDRAIL_CACHE_SQLITE_PATH cache-sqlite-path
export_if_set GUARDRAIL_POLICY_PATH policy
export_if_set GUARDRAIL_OUTPUT_JSON output-json
export_if_set GUARDRAIL_OUTPUT_MARKDOWN output-markdown
export_if_set GUARDRAIL_OUTPUT_SARIF output-sarif
export_if_set GUARDRAIL_PR_COMMENT_MODE pr-comment-mode
export_if_set GUARDRAIL_GITHUB_TOKEN github-token
export_if_set GUARDRAIL_PR_NUMBER pr-number
export_if_set GUARDRAIL_REPOSITORY repository
export_if_set GUARDRAIL_COMMIT_SHA commit-sha
export_if_set GUARDRAIL_SEMANTIC_COMPLIANCE semantic-compliance
export_if_set GUARDRAIL_VECTOR_STORE_PATH vector-store-path
export_if_set GUARDRAIL_CONTEXT_STRATEGY context-strategy

set -- "$@"

format=$(input_value format)
if [ -n "$format" ]; then
  set -- "$@" --format "$format"
fi

language=$(input_value language)
if [ -n "$language" ] && [ "$language" != "auto" ]; then
  set -- "$@" --language "$language"
fi

repo_root=$(input_value repo-root)
if [ -n "$repo_root" ]; then
  set -- "$@" --repo-root "$repo_root"
fi

exec guardrail "$@"
