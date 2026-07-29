"""Compliance framework integration."""

from __future__ import annotations

from collections.abc import Iterable

from guardrail.compliance.base import (
    CISAWSMapper,
    ComplianceMapper,
    ComplianceRegistry,
    GenericCWEMapper,
    OWASPMapper,
    RulesetMapper,
)
from guardrail.compliance.cert_c import CERT_C_RULES
from guardrail.compliance.fips import FIPS_RULES
from guardrail.compliance.misra_c import MISRA_C_RULES
from guardrail.models import ComplianceHit, Finding, Language

__all__ = [
    "ComplianceRegistry",
    "ComplianceMapper",
    "RulesetMapper",
    "GenericCWEMapper",
    "OWASPMapper",
    "CISAWSMapper",
    "compliance_hits_for_cwe",
    "list_frameworks",
    "get_rule",
]


# Build the default registry once at import time.
_REGISTRY = ComplianceRegistry()
_REGISTRY.register(RulesetMapper("cert_c", CERT_C_RULES))
_REGISTRY.register(RulesetMapper("misra_c", MISRA_C_RULES))
_REGISTRY.register(RulesetMapper("fips", FIPS_RULES))
_REGISTRY.register(GenericCWEMapper())
_REGISTRY.register(OWASPMapper())
_REGISTRY.register(CISAWSMapper())


class ComplianceProxy:
    """Thin proxy that exposes the legacy API while delegating to the registry."""

    @staticmethod
    def list_frameworks() -> list[str]:
        return _REGISTRY.frameworks()

    @staticmethod
    def get_rule(framework: str, rule_id: str) -> dict | None:
        mapper = _REGISTRY.get(framework)
        if isinstance(mapper, RulesetMapper):
            return mapper._rules.get(rule_id)
        return None

    @staticmethod
    def compliance_hits_for_cwe(
        cwe: str | None,
        frameworks: Iterable[str] | None = None,
    ) -> list[ComplianceHit]:
        # Build a dummy finding so we can use the registry API.
        finding = Finding(
            rule_id="",
            message="",
            file_path="",
            cwe=cwe,
        )
        # The legacy API defaults to all registered frameworks when none are supplied.
        if frameworks is None:
            frameworks = _REGISTRY.frameworks()
        return _REGISTRY.map_finding(finding, frameworks=frameworks, language=Language.UNKNOWN)


list_frameworks = ComplianceProxy.list_frameworks
get_rule = ComplianceProxy.get_rule
compliance_hits_for_cwe = ComplianceProxy.compliance_hits_for_cwe


def default_registry() -> ComplianceRegistry:
    """Return the built-in compliance registry with all rulesets."""
    return _REGISTRY
