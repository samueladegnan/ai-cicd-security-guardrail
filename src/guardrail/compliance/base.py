"""Pluggable compliance mapping for the guardrail.

The guardrail ships with language-specific compliance rules (CERT C, MISRA C,
FIPS) and generic cross-language mappers (OWASP, CWE, CIS AWS).  Each mapper
implements :class:`ComplianceMapper` and is registered in a global registry.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from guardrail.models import ComplianceHit, Finding, Language


class ComplianceMapper(ABC):
    """Map a finding to compliance controls."""

    framework: str = ""

    @abstractmethod
    def map_finding(
        self, finding: Finding, frameworks: Iterable[str] | None = None
    ) -> list[ComplianceHit]:
        """Return compliance hits for a single finding."""


class RulesetMapper(ComplianceMapper):
    """Mapper backed by a static dictionary of rules keyed by rule ID."""

    def __init__(self, framework: str, rules: dict[str, dict[str, Any]]):
        self.framework = framework
        self._rules = rules

    def map_finding(
        self, finding: Finding, frameworks: Iterable[str] | None = None
    ) -> list[ComplianceHit]:
        if frameworks is not None and self.framework not in frameworks:
            return []
        return self._map_cwe(finding.cwe)

    def _map_cwe(self, cwe: str | None) -> list[ComplianceHit]:
        normalized = _normalize_cwe(cwe)
        hits: list[ComplianceHit] = []
        for rule_id, rule in self._rules.items():
            cwes = {c.upper() for c in rule.get("cwes", [])}
            if normalized and normalized in cwes:
                hits.append(
                    ComplianceHit(
                        framework=self.framework,
                        rule_id=rule_id,
                        title=rule.get("title", ""),
                        description=rule.get("description", ""),
                    )
                )
        return hits


class GenericCWEMapper(ComplianceMapper):
    """Generic mapper that emits a compliance hit for any known CWE.

    This lets the guardrail produce useful context even when a tool does not
    belong to a language-specific framework.
    """

    framework = "cwe"

    HIGH_RISK_CWES = {
        "CWE-79",
        "CWE-89",
        "CWE-94",
        "CWE-119",
        "CWE-120",
        "CWE-121",
        "CWE-122",
        "CWE-125",
        "CWE-131",
        "CWE-190",
        "CWE-200",
        "CWE-209",
        "CWE-295",
        "CWE-312",
        "CWE-319",
        "CWE-327",
        "CWE-330",
        "CWE-352",
        "CWE-416",
        "CWE-434",
        "CWE-502",
        "CWE-522",
        "CWE-798",
        "CWE-915",
    }

    def map_finding(
        self, finding: Finding, frameworks: Iterable[str] | None = None
    ) -> list[ComplianceHit]:
        if frameworks is not None and self.framework not in frameworks:
            return []
        normalized = _normalize_cwe(finding.cwe)
        if not normalized or normalized not in self.HIGH_RISK_CWES:
            return []
        return [
            ComplianceHit(
                framework=self.framework,
                rule_id=normalized,
                title=f"Common Weakness: {normalized}",
                description=f"{normalized} is referenced by this finding. See https://cwe.mitre.org/data/definitions/{normalized.replace('CWE-', '')}.html",
            )
        ]


class OWASPMapper(ComplianceMapper):
    """Generic OWASP Top 10 mapper driven by CWE-to-category heuristics."""

    framework = "owasp"

    # Mapping from CWE to the most relevant OWASP Top 10 2021 category.
    _CWE_TO_OWASP: dict[str, list[str]] = {
        "CWE-79": ["A03:2021 – Injection"],
        "CWE-89": ["A03:2021 – Injection"],
        "CWE-94": ["A03:2021 – Injection"],
        "CWE-120": ["A03:2021 – Injection"],
        "CWE-121": ["A03:2021 – Injection"],
        "CWE-122": ["A03:2021 – Injection"],
        "CWE-125": ["A03:2021 – Injection"],
        "CWE-190": ["A03:2021 – Injection"],
        "CWE-287": ["A07:2021 – Identification and Authentication Failures"],
        "CWE-295": ["A07:2021 – Identification and Authentication Failures"],
        "CWE-306": ["A07:2021 – Identification and Authentication Failures"],
        "CWE-522": ["A07:2021 – Identification and Authentication Failures"],
        "CWE-798": ["A07:2021 – Identification and Authentication Failures"],
        "CWE-307": ["A07:2021 – Identification and Authentication Failures"],
        "CWE-311": ["A02:2021 – Cryptographic Failures"],
        "CWE-319": ["A02:2021 – Cryptographic Failures"],
        "CWE-327": ["A02:2021 – Cryptographic Failures"],
        "CWE-330": ["A02:2021 – Cryptographic Failures"],
        "CWE-338": ["A02:2021 – Cryptographic Failures"],
        "CWE-200": ["A01:2021 – Broken Access Control"],
        "CWE-201": ["A01:2021 – Broken Access Control"],
        "CWE-352": ["A01:2021 – Broken Access Control"],
        "CWE-209": ["A05:2021 – Security Misconfiguration"],
        "CWE-312": ["A05:2021 – Security Misconfiguration"],
        "CWE-548": ["A05:2021 – Security Misconfiguration"],
        "CWE-434": ["A04:2021 – Insecure Design"],
        "CWE-502": ["A08:2021 – Software and Data Integrity Failures"],
        "CWE-915": ["A01:2021 – Broken Access Control"],
        "CWE-416": ["A03:2021 – Injection"],
        "CWE-415": ["A03:2021 – Injection"],
        "CWE-590": ["A03:2021 – Injection"],
    }

    def map_finding(
        self, finding: Finding, frameworks: Iterable[str] | None = None
    ) -> list[ComplianceHit]:
        if frameworks is not None and self.framework not in frameworks:
            return []
        normalized = _normalize_cwe(finding.cwe)
        categories = self._CWE_TO_OWASP.get(normalized, [])
        if not categories:
            return []
        return [
            ComplianceHit(
                framework=self.framework,
                rule_id=cat,
                title=cat,
                description=f"OWASP Top 10 mapping for {normalized}.",
            )
            for cat in categories
        ]


class CISAWSMapper(ComplianceMapper):
    """CIS AWS Foundations Benchmark mapper for Terraform/IaC findings."""

    framework = "cis_aws"

    _CWE_TO_CIS: dict[str, list[str]] = {
        "CWE-200": ["CIS AWS 1.20 – Ensure S3 bucket access is configured"],
        "CWE-201": ["CIS AWS 1.20 – Ensure S3 bucket access is configured"],
        "CWE-311": ["CIS AWS 2.1.1 – Ensure EBS snapshots are encrypted"],
        "CWE-312": ["CIS AWS 2.1.1 – Ensure EBS snapshots are encrypted"],
        "CWE-319": ["CIS AWS 2.1.1 – Ensure EBS snapshots are encrypted"],
        "CWE-798": ["CIS AWS 1.12 – Ensure IAM password policy exists"],
    }

    def map_finding(
        self, finding: Finding, frameworks: Iterable[str] | None = None
    ) -> list[ComplianceHit]:
        if frameworks is not None and self.framework not in frameworks:
            return []
        normalized = _normalize_cwe(finding.cwe)
        categories = self._CWE_TO_CIS.get(normalized, [])
        if not categories:
            return []
        return [
            ComplianceHit(
                framework=self.framework,
                rule_id=cat,
                title=cat,
                description=f"CIS AWS mapping for {normalized}.",
            )
            for cat in categories
        ]


class ComplianceRegistry:
    """Registry of compliance mappers."""

    def __init__(self) -> None:
        self._mappers: dict[str, ComplianceMapper] = {}

    def register(self, mapper: ComplianceMapper) -> None:
        self._mappers[mapper.framework.lower()] = mapper

    def get(self, framework: str) -> ComplianceMapper | None:
        return self._mappers.get(framework.lower())

    def frameworks(self) -> list[str]:
        return list(self._mappers.keys())

    def map_finding(
        self,
        finding: Finding,
        frameworks: Iterable[str] | None = None,
        language: Language = Language.UNKNOWN,
    ) -> list[ComplianceHit]:
        """Map a finding to compliance hits across selected frameworks.

        If ``frameworks`` is omitted, a sensible default set is chosen from the
        finding's language.
        """
        if frameworks is None:
            frameworks = _default_frameworks_for(language)
        frameworks = {f.lower() for f in frameworks}
        hits: list[ComplianceHit] = []
        for framework in frameworks:
            mapper = self._mappers.get(framework)
            if mapper:
                hits.extend(mapper.map_finding(finding, frameworks=[framework]))
        return hits

    @classmethod
    def default(cls) -> ComplianceRegistry:
        registry = cls()
        registry.register(GenericCWEMapper())
        registry.register(OWASPMapper())
        registry.register(CISAWSMapper())
        return registry


def _normalize_cwe(cwe: str | None) -> str:
    if not cwe:
        return ""
    cwe = cwe.upper().strip()
    if cwe.startswith("CWE-"):
        return cwe
    if cwe.isdigit():
        return f"CWE-{cwe}"
    return cwe


def _default_frameworks_for(language: Language) -> list[str]:
    if language in {Language.C, Language.CPP, Language.C_Family}:
        return ["cert_c", "misra_c", "fips", "cwe"]
    if language == Language.TERRAFORM:
        return ["cis_aws", "cwe"]
    return ["owasp", "cwe"]
