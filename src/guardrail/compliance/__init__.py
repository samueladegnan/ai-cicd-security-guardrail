"""Compliance framework integration."""

from __future__ import annotations

from typing import Iterable

from guardrail.compliance.cert_c import CERT_C_RULES
from guardrail.compliance.fips import FIPS_RULES
from guardrail.compliance.misra_c import MISRA_C_RULES
from guardrail.models import ComplianceHit

_ALL_RULESETS = {
    "cert_c": CERT_C_RULES,
    "misra_c": MISRA_C_RULES,
    "fips": FIPS_RULES,
}


def list_frameworks() -> list[str]:
    """Return supported compliance framework identifiers."""
    return list(_ALL_RULESETS.keys())


def get_rule(framework: str, rule_id: str) -> dict | None:
    """Return a single rule definition from a framework."""
    ruleset = _ALL_RULESETS.get(framework.lower())
    if not ruleset:
        return None
    return ruleset.get(rule_id)


def _normalize_cwe(cwe: str | None) -> str:
    if not cwe:
        return ""
    cwe = cwe.upper().strip()
    if cwe.startswith("CWE-"):
        return cwe
    if cwe.isdigit():
        return f"CWE-{cwe}"
    return cwe


def compliance_hits_for_cwe(cwe: str | None, frameworks: Iterable[str] | None = None) -> list[ComplianceHit]:
    """Return the compliance controls related to a given CWE.

    This lightweight lookup avoids a giant hard-coded matrix by using the
    CWE-to-framework mappings embedded in each ruleset.
    """
    if frameworks is None:
        frameworks = list_frameworks()
    normalized = _normalize_cwe(cwe)
    hits: list[ComplianceHit] = []
    for framework in frameworks:
        ruleset = _ALL_RULESETS.get(framework.lower())
        if not ruleset:
            continue
        for rule_id, rule in ruleset.items():
            cwes = {c.upper() for c in rule.get("cwes", [])}
            if normalized and normalized in cwes:
                hits.append(
                    ComplianceHit(
                        framework=framework,
                        rule_id=rule_id,
                        title=rule.get("title", ""),
                        description=rule.get("description", ""),
                    )
                )
    return hits