"""Base parser abstraction for the guardrail."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from guardrail.models import Finding, Language


class BaseReportParser(ABC):
    """Abstract base class for static-analysis report parsers."""

    @property
    @abstractmethod
    def tool(self) -> str:
        """Human-readable tool identifier (e.g. 'sarif', 'sonarqube')."""

    @property
    @abstractmethod
    def supported_languages(self) -> tuple[Language, ...]:
        """Languages this parser is typically used for."""

    @abstractmethod
    def parse(self, path: str) -> list[Finding]:
        """Parse a report into findings."""


class InMemoryParser(BaseReportParser):
    """Helper for tests: parse a raw data structure."""

    def __init__(self, tool: str, data: dict[str, Any]) -> None:
        self._tool = tool
        self._data = data
        self._supported_languages = (Language.UNKNOWN,)

    @property
    def tool(self) -> str:
        return self._tool

    @property
    def supported_languages(self) -> tuple[Language, ...]:
        return self._supported_languages

    def parse(self, path: str) -> list[Finding]:
        raise NotImplementedError("InMemoryParser is intended for subclassing in tests.")
