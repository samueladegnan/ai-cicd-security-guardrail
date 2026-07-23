"""Pydantic models for the guardrail pipeline."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TriageVerdict(str, Enum):
    HIGH_PRIORITY = "HIGH_PRIORITY"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNCLEAR = "UNCLEAR"


class Finding(BaseModel):
    """A single static analysis warning."""

    rule_id: str = Field(..., description="Static analysis rule identifier.")
    message: str = Field(..., description="Human-readable warning message.")
    file_path: str = Field(..., description="Path to the source file.")
    line: int = Field(default=0, description="Line number in the source file.")
    column: int = Field(default=0, description="Column number in the source file.")
    severity: Severity = Field(default=Severity.MEDIUM)
    code_snippet: str = Field(default="", description="Lines of code around the warning.")
    cwe: Optional[str] = Field(default=None, description="CWE identifier if available.")
    tool: str = Field(default="unknown", description="Source static analysis tool.")
    raw: Dict[str, Any] = Field(default_factory=dict, description="Raw finding payload.")

    model_config = ConfigDict(frozen=True)


class ComplianceHit(BaseModel):
    """A compliance control that a finding may violate."""

    framework: str = Field(..., description="e.g. cert_c, misra_c, fips")
    rule_id: str = Field(..., description="Rule identifier within the framework.")
    title: str = Field(default="")
    description: str = Field(default="")


class TriageResult(BaseModel):
    """Result of LLM triage for a single finding."""

    finding: Finding
    verdict: TriageVerdict
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = Field(default="")
    compliance_hits: List[ComplianceHit] = Field(default_factory=list)
    remediation: str = Field(default="")


class Summary(BaseModel):
    total: int = 0
    high_priority: int = 0
    false_positive: int = 0
    unclear: int = 0


class Report(BaseModel):
    """Final triage report."""

    summary: Summary = Field(default_factory=Summary)
    results: List[TriageResult] = Field(default_factory=list)

    def compute_summary(self) -> None:
        summary = Summary(total=len(self.results))
        for result in self.results:
            if result.verdict == TriageVerdict.HIGH_PRIORITY:
                summary.high_priority += 1
            elif result.verdict == TriageVerdict.FALSE_POSITIVE:
                summary.false_positive += 1
            elif result.verdict == TriageVerdict.UNCLEAR:
                summary.unclear += 1
        self.summary = summary