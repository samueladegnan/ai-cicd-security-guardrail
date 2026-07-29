#!/usr/bin/env python3
"""Synthetic benchmark for the guardrail classifier.

Run with:
    python benchmarks/evaluate.py --provider mock

The benchmark loads a small labeled dataset of findings, runs the guardrail
through the real engine, and reports precision, recall, F1, and latency.
"""

from __future__ import annotations

import argparse
import time
from typing import List

from guardrail.config import Settings
from guardrail.models import Finding, Language, Severity, TriageVerdict
from guardrail.triage import TriageEngine


class LabeledFinding:
    def __init__(self, finding: Finding, expected: TriageVerdict):
        self.finding = finding
        self.expected = expected


SAMPLES: List[LabeledFinding] = [
    LabeledFinding(
        Finding(
            rule_id="CWE-121",
            message="Possible stack-based buffer overflow due to unchecked strcpy.",
            file_path="sample_code/vulnerable.c",
            line=14,
            severity=Severity.HIGH,
            language=Language.C,
            cwe="CWE-121",
            tool="demo-sast",
        ),
        TriageVerdict.HIGH_PRIORITY,
    ),
    LabeledFinding(
        Finding(
            rule_id="unused-variable",
            message="Local variable 'result' is assigned but never used.",
            file_path="sample_code/false_positive.c",
            line=13,
            severity=Severity.LOW,
            language=Language.C,
            tool="demo-sast",
        ),
        TriageVerdict.FALSE_POSITIVE,
    ),
    LabeledFinding(
        Finding(
            rule_id="CWE-457",
            message="Variable 'total' may be used before it is initialized.",
            file_path="sample_code/vulnerable.c",
            line=22,
            severity=Severity.MEDIUM,
            language=Language.C,
            cwe="CWE-457",
            tool="demo-sast",
        ),
        TriageVerdict.HIGH_PRIORITY,
    ),
    LabeledFinding(
        Finding(
            rule_id="missing-default-case",
            message="Switch statement does not have a default case.",
            file_path="sample_code/vulnerable.c",
            line=35,
            severity=Severity.LOW,
            language=Language.C,
            tool="demo-sast",
        ),
        TriageVerdict.UNCLEAR,
    ),
]


def run_benchmark(provider: str) -> None:
    settings = Settings.from_env()
    settings = settings.__class__(
        **{**settings.__dict__, "llm_provider": provider, "cache_enabled": False}
    )
    engine = TriageEngine(settings)

    findings = [sample.finding for sample in SAMPLES]
    start = time.perf_counter()
    report = engine.run_concurrent(findings)
    elapsed = time.perf_counter() - start

    correct = 0
    confusion = {v.value: {"tp": 0, "fp": 0, "fn": 0} for v in TriageVerdict}
    for sample, result in zip(SAMPLES, report.results):
        expected = sample.expected.value
        actual = result.verdict.value
        if expected == actual:
            correct += 1
            confusion[expected]["tp"] += 1
        else:
            confusion[actual]["fp"] += 1
            confusion[expected]["fn"] += 1

    total = len(SAMPLES)
    accuracy = correct / total if total else 0.0
    print(f"Provider: {provider}")
    print(f"Accuracy: {accuracy:.0%} ({correct}/{total})")
    print(f"Latency:  {elapsed:.3f}s ({elapsed / total:.3f}s per finding)")
    print("\nConfusion matrix:")
    for verdict, counts in confusion.items():
        precision = counts["tp"] / (counts["tp"] + counts["fp"]) if (counts["tp"] + counts["fp"]) else 0
        recall = counts["tp"] / (counts["tp"] + counts["fn"]) if (counts["tp"] + counts["fn"]) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        print(f"  {verdict}: precision={precision:.2f} recall={recall:.2f} f1={f1:.2f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark guardrail classifier.")
    parser.add_argument("--provider", default="mock", help="LLM provider to benchmark.")
    args = parser.parse_args()
    run_benchmark(args.provider)


if __name__ == "__main__":
    main()
