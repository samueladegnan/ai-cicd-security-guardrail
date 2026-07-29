"""In-memory circuit breaker for LLM provider resilience."""

from __future__ import annotations

import threading
import time
from typing import Any


class CircuitBreaker:
    """Simple in-memory circuit breaker for LLM provider resilience."""

    _state: dict[str, dict[str, Any]] = {}
    _lock = threading.Lock()

    def __init__(self, name: str, threshold: int = 5, timeout_seconds: int = 60):
        self.name = name
        self.threshold = threshold
        self.timeout_seconds = timeout_seconds

    def _record(self) -> dict[str, Any]:
        with self._lock:
            if self.name not in self._state:
                self._state[self.name] = {"failures": 0, "last_failure": 0.0, "open": False}
            return self._state[self.name]

    def is_open(self) -> bool:
        record = self._record()
        if record["open"]:
            if time.time() - record["last_failure"] > self.timeout_seconds:
                with self._lock:
                    record["open"] = False
                    record["failures"] = 0
                return False
            return True
        return False

    def record_success(self) -> None:
        record = self._record()
        with self._lock:
            record["failures"] = 0
            record["open"] = False

    def record_failure(self) -> None:
        record = self._record()
        with self._lock:
            record["failures"] += 1
            record["last_failure"] = time.time()
            if record["failures"] >= self.threshold:
                record["open"] = True
