"""
Unit tests for EC2 security group misconfiguration detection rules.
All tests use inline data — no real AWS calls.
"""
import pytest

from analyzers.ec2_rules import (
    CRITICAL_PORTS,
    analyze_security_group,
    classify_rule,
    is_all_ports,
    is_world_open,
)
from models import InboundRule, SecurityGroupConfig, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule(**kwargs) -> InboundRule:
    defaults = {
        "protocol": "tcp",
        "from_port": None,
        "to_port": None,
        "cidr_ipv4": None,
        "cidr_ipv6": None,
    }
    defaults.update(kwargs)
    return InboundRule.model_validate(defaults)


def _sg(rules: list[InboundRule], group_id: str = "sg-test-001", name: str = "test-sg") -> SecurityGroupConfig:
    return SecurityGroupConfig(
        group_id=group_id,
        group_name=name,
        description="Test security group",
        inbound_rules=rules,
    )


# ---------------------------------------------------------------------------
# is_world_open
# ---------------------------------------------------------------------------

def test_world_open_ipv4():
    assert is_world_open(_rule(cidr_ipv4="0.0.0.0/0")) is True


def test_world_open_ipv6():
    assert is_world_open(_rule(cidr_ipv6="::/0")) is True


def test_not_world_open_private_cidr():
    assert is_world_open(_rule(cidr_ipv4="10.0.0.0/8")) is False


def test_not_world_open_no_cidr():
    assert is_world_open(_rule()) is False


# ---------------------------------------------------------------------------
# is_all_ports
# ---------------------------------------------------------------------------

def test_all_ports_protocol_minus1():
    assert is_all_ports(_rule(protocol="-1")) is True


def test_all_ports_range_0_65535():
    assert is_all_ports(_rule(from_port=0, to_port=65535)) is True


def test_not_all_ports_specific_port():
    assert is_all_ports(_rule(from_port=22, to_port=22)) is False


# ---------------------------------------------------------------------------
# classify_rule
# ---------------------------------------------------------------------------

def test_critical_ssh_ipv4():
    rule = _rule(from_port=22, to_port=22, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Critical


def test_critical_ssh_ipv6():
    rule = _rule(from_port=22, to_port=22, cidr_ipv6="::/0")
    assert classify_rule(rule) == Severity.Critical


def test_critical_rdp():
    rule = _rule(from_port=3389, to_port=3389, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Critical


def test_critical_mysql():
    rule = _rule(from_port=3306, to_port=3306, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Critical


def test_critical_postgres():
    rule = _rule(from_port=5432, to_port=5432, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Critical


def test_critical_mssql():
    rule = _rule(from_port=1433, to_port=1433, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Critical


def test_critical_mongodb():
    rule = _rule(from_port=27017, to_port=27017, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Critical


def test_critical_all_ports_protocol():
    rule = _rule(protocol="-1", cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Critical


def test_critical_all_ports_range():
    rule = _rule(from_port=0, to_port=65535, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Critical


def test_high_custom_port_8080():
    rule = _rule(from_port=8080, to_port=8080, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.High


def test_high_redis():
    rule = _rule(from_port=6379, to_port=6379, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.High


def test_informational_http():
    rule = _rule(from_port=80, to_port=80, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Informational


def test_informational_https():
    rule = _rule(from_port=443, to_port=443, cidr_ipv4="0.0.0.0/0")
    assert classify_rule(rule) == Severity.Informational


def test_none_when_restricted_cidr():
    rule = _rule(from_port=22, to_port=22, cidr_ipv4="10.0.0.0/8")
    assert classify_rule(rule) is None


def test_none_when_no_cidr():
    rule = _rule(from_port=22, to_port=22)
    assert classify_rule(rule) is None


# ---------------------------------------------------------------------------
# analyze_security_group
# ---------------------------------------------------------------------------

def test_all_ports_suppresses_individual_ports():
    """A group with an all-ports rule should produce exactly one Critical finding."""
    rules = [
        _rule(protocol="-1", cidr_ipv4="0.0.0.0/0"),
        _rule(from_port=22, to_port=22, cidr_ipv4="0.0.0.0/0"),
    ]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    assert len(findings) == 1
    assert findings[0].severity == Severity.Critical


def test_consolidation_same_port_ipv4_ipv6():
    """Two rules on the same port (IPv4 + IPv6) should produce one consolidated finding."""
    rules = [
        _rule(from_port=22, to_port=22, cidr_ipv4="0.0.0.0/0"),
        _rule(from_port=22, to_port=22, cidr_ipv6="::/0"),
    ]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    ssh_findings = [f for f in findings if "22" in str(f.evidence.get("port", "")) or "22" in f.title]
    assert len(ssh_findings) == 1
    # Both rules should appear in evidence
    matching_rules = ssh_findings[0].evidence.get("matching_rules", [])
    assert len(matching_rules) == 2


def test_no_findings_for_restricted_sg():
    """A fully restricted security group should produce no findings."""
    rules = [
        _rule(from_port=443, to_port=443, cidr_ipv4="10.0.0.0/8"),
        _rule(from_port=5432, to_port=5432, cidr_ipv4="172.16.0.0/12"),
    ]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    assert findings == []


def test_only_informational_for_web_sg():
    """A group with only 80 and 443 open to world produces only Informational findings."""
    rules = [
        _rule(from_port=80, to_port=80, cidr_ipv4="0.0.0.0/0"),
        _rule(from_port=443, to_port=443, cidr_ipv4="0.0.0.0/0"),
    ]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    assert all(f.severity == Severity.Informational for f in findings)


def test_critical_ssh_finding():
    """World-open SSH produces Critical finding."""
    rules = [_rule(from_port=22, to_port=22, cidr_ipv4="0.0.0.0/0")]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    assert any(f.severity == Severity.Critical for f in findings)


def test_high_finding_custom_port():
    """World-open non-standard port produces High finding."""
    rules = [_rule(from_port=8080, to_port=8080, cidr_ipv4="0.0.0.0/0")]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    assert any(f.severity == Severity.High for f in findings)


def test_all_findings_have_evidence():
    """All findings must have non-empty evidence dicts with group_id."""
    rules = [
        _rule(from_port=22, to_port=22, cidr_ipv4="0.0.0.0/0"),
        _rule(from_port=80, to_port=80, cidr_ipv4="0.0.0.0/0"),
    ]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    for f in findings:
        assert isinstance(f.evidence, dict)
        assert "group_id" in f.evidence


def test_all_findings_simulated_true():
    """All EC2 findings must have simulated=True."""
    rules = [_rule(from_port=3306, to_port=3306, cidr_ipv4="0.0.0.0/0")]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    for f in findings:
        assert f.simulated is True


def test_risk_explanation_mentions_simulated():
    """Risk explanation must state this is simulated data."""
    rules = [_rule(from_port=22, to_port=22, cidr_ipv4="0.0.0.0/0")]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    for f in findings:
        assert "simulated configuration data" in f.risk_explanation


def test_ipv6_world_open_triggers_finding():
    """IPv6 ::/0 rules trigger findings."""
    rules = [_rule(from_port=22, to_port=22, cidr_ipv6="::/0")]
    sg = _sg(rules)
    findings = analyze_security_group(sg)
    assert any(f.severity == Severity.Critical for f in findings)
