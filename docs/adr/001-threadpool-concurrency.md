# ADR 001: ThreadPoolExecutor for concurrent LLM calls

## Status

Accepted

## Context

The guardrail triage engine classifies each static-analysis finding independently, which makes it natural to process findings concurrently. We needed to decide between `asyncio` and `concurrent.futures.ThreadPoolExecutor`.

## Decision

We use `ThreadPoolExecutor` with a configurable `max_workers` value.

## Consequences

- **Simpler integration with synchronous HTTP clients.** The project uses `requests` for all LLM providers. Wrapping every client in async scaffolding would add complexity without improving throughput for a small number of findings.
- **Bounded concurrency.** `ThreadPoolExecutor` gives us explicit control over the number of simultaneous LLM calls, avoiding accidental provider rate-limit violations.
- **Blocking I/O is acceptable.** Each LLM call is network-bound. The GIL is released during I/O, so threads are not a bottleneck for this workload.
- **Future option.** If throughput becomes a concern, we can replace the executor with an small `asyncio` layer that reuses the same provider logic.
