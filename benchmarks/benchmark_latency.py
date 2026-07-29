"""Benchmark guardrail latency and generate a simple SBOM.

Run with:
    python benchmarks/benchmark_latency.py

Outputs:
    benchmarks/latency-report.json
    benchmarks/sbom.json
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = ROOT / "tests" / "fixtures" / "sample.sarif"


def run_guardrail(provider: str = "mock") -> dict[str, float]:
    """Run the guardrail CLI and return elapsed seconds."""
    start = time.perf_counter()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "guardrail",
            str(REPORT_PATH),
            "--repo-root",
            str(ROOT),
            "--provider",
            provider,
            "--output-json",
            str(ROOT / "benchmarks" / "guardrail-benchmark.json"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    elapsed = time.perf_counter() - start
    return {"provider": provider, "elapsed_seconds": round(elapsed, 4)}


def generate_sbom() -> list[dict[str, str]]:
    """Generate a simple SBOM from installed packages."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        capture_output=True,
        text=True,
        check=True,
    )
    packages = json.loads(result.stdout)
    return [
        {"name": pkg["name"], "version": pkg["version"]}
        for pkg in packages
    ]


def main() -> None:
    benchmark_dir = ROOT / "benchmarks"
    benchmark_dir.mkdir(exist_ok=True)

    print("Running guardrail latency benchmark...")
    latency = run_guardrail(provider="mock")

    print("Generating SBOM...")
    sbom = generate_sbom()

    latency_report = {
        "tool": "ai-cicd-security-guardrail",
        "benchmark": "cli-latency",
        **latency,
    }
    (benchmark_dir / "latency-report.json").write_text(
        json.dumps(latency_report, indent=2), encoding="utf-8"
    )
    (benchmark_dir / "sbom.json").write_text(
        json.dumps(sbom, indent=2), encoding="utf-8"
    )

    print(f"Latency: {latency['elapsed_seconds']}s")
    print(f"SBOM packages: {len(sbom)}")
    print(f"Reports written to {benchmark_dir}")


if __name__ == "__main__":
    main()
