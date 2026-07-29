"""Tests for pluggable compliance mapping."""

from __future__ import annotations

from guardrail.compliance import ComplianceRegistry, compliance_hits_for_cwe, list_frameworks
from guardrail.compliance.base import CISAWSMapper, GenericCWEMapper, OWASPMapper, RulesetMapper
from guardrail.compliance.cert_c import CERT_C_RULES
from guardrail.compliance.fips import FIPS_RULES
from guardrail.compliance.misra_c import MISRA_C_RULES
from guardrail.models import Finding, Language


def test_list_frameworks_contains_old_and_new():
    frameworks = set(list_frameworks())
    assert "cert_c" in frameworks
    assert "misra_c" in frameworks
    assert "fips" in frameworks
    assert "cwe" in frameworks
    assert "owasp" in frameworks
    assert "cis_aws" in frameworks


def test_compliance_hits_for_cwe_cert_c():
    hits = compliance_hits_for_cwe("CWE-121")
    assert any(hit.framework == "cert_c" for hit in hits)


def test_generic_cwe_mapper():
    registry = ComplianceRegistry.default()
    finding = Finding(rule_id="test", message="test", file_path="x.rb", cwe="CWE-79")
    hits = registry.map_finding(finding, frameworks=["cwe"], language=Language.RUBY)
    assert any(hit.framework == "cwe" and hit.rule_id == "CWE-79" for hit in hits)


def test_owasp_mapper_injection():
    mapper = OWASPMapper()
    finding = Finding(rule_id="sql", message="SQL injection", file_path="app.rb", cwe="CWE-89")
    hits = mapper.map_finding(finding)
    assert any("Injection" in hit.rule_id for hit in hits)


def test_cis_aws_mapper_encryption():
    mapper = CISAWSMapper()
    finding = Finding(rule_id="s3", message="unencrypted", file_path="main.tf", cwe="CWE-311")
    hits = mapper.map_finding(finding)
    assert any("EBS" in hit.rule_id for hit in hits)


def _registry_with_rulesets():
    registry = ComplianceRegistry()
    registry.register(RulesetMapper("cert_c", CERT_C_RULES))
    registry.register(RulesetMapper("misra_c", MISRA_C_RULES))
    registry.register(RulesetMapper("fips", FIPS_RULES))
    registry.register(GenericCWEMapper())
    registry.register(OWASPMapper())
    registry.register(CISAWSMapper())
    return registry


def test_default_frameworks_for_c_family():
    registry = _registry_with_rulesets()
    finding = Finding(rule_id="x", message="x", file_path="x.c", cwe="CWE-121")
    hits = registry.map_finding(finding, language=Language.C)
    assert any(hit.framework == "cert_c" for hit in hits)


def test_default_frameworks_for_terraform():
    registry = _registry_with_rulesets()
    finding = Finding(rule_id="x", message="x", file_path="x.tf", cwe="CWE-798")
    hits = registry.map_finding(finding, language=Language.TERRAFORM)
    assert any(hit.framework == "cis_aws" for hit in hits)


def test_registry_get_returns_mapper():
    registry = _registry_with_rulesets()
    assert registry.get("cert_c") is not None
    assert registry.get("owasp") is not None
    assert registry.get("missing") is None


def test_registry_default_includes_generic_mappers():
    from guardrail.compliance.base import ComplianceRegistry

    registry = ComplianceRegistry.default()
    assert "cwe" in registry.frameworks()
    assert "owasp" in registry.frameworks()
    assert "cis_aws" in registry.frameworks()


def test_owasp_mapper_returns_empty_for_unknown_cwe():
    from guardrail.compliance.base import OWASPMapper

    mapper = OWASPMapper()
    finding = Finding(rule_id="x", message="x", file_path="x.c", cwe="CWE-999")
    assert mapper.map_finding(finding) == []


def test_cis_aws_mapper_encryption_ebs():
    from guardrail.compliance.base import CISAWSMapper

    mapper = CISAWSMapper()
    finding = Finding(rule_id="x", message="x", file_path="x.tf", cwe="CWE-311")
    hits = mapper.map_finding(finding)
    assert any("EBS" in hit.rule_id for hit in hits)
