"""
Integration tests for the Scanner orchestrator using SimulatedScannerProvider.
No real AWS calls are made.
"""
# MOCKED: All AWS interactions in this file use mock/moto — no real AWS account required
import sys

import pytest

from models import Severity, ScanResult
from providers.simulated import SimulatedScannerProvider
from scanner import Scanner

VALID_SEVERITIES = {s.value for s in Severity}


@pytest.fixture
def scan_result() -> ScanResult:
    """Run a full scan with the real fixture files and return the result."""
    provider = SimulatedScannerProvider()
    scanner = Scanner(provider)
    return scanner.run()


def test_full_scan_returns_scan_result(scan_result):
    """Scan returns a ScanResult instance."""
    assert isinstance(scan_result, ScanResult)


def test_scan_has_findings(scan_result):
    """Scan produces at least one finding."""
    assert len(scan_result.findings) > 0


def test_all_findings_have_required_fields(scan_result):
    """Every finding has all required fields populated."""
    for finding in scan_result.findings:
        assert finding.resource_type in ("S3Bucket", "SecurityGroup"), f"Invalid resource_type: {finding.resource_type}"
        assert finding.resource_name, f"Empty resource_name on finding {finding.id}"
        assert finding.severity.value in VALID_SEVERITIES
        assert finding.title, "Empty title"
        assert isinstance(finding.evidence, dict) and len(finding.evidence) > 0
        assert finding.risk_explanation, "Empty risk_explanation"
        assert finding.remediation, "Empty remediation"


def test_all_findings_simulated_true(scan_result):
    """All findings must have simulated=True."""
    for finding in scan_result.findings:
        assert finding.simulated is True, f"Finding {finding.id} has simulated=False"


def test_scan_result_simulated_true(scan_result):
    """ScanResult.simulated must be True."""
    assert scan_result.simulated is True


def test_summary_matches_findings(scan_result):
    """Summary counts must match the actual findings distribution."""
    from collections import Counter
    actual_counts = Counter(f.severity.value for f in scan_result.findings)
    for severity_val, count in scan_result.summary.items():
        assert count == actual_counts.get(severity_val, 0), (
            f"Summary mismatch for {severity_val}: summary={count}, actual={actual_counts.get(severity_val, 0)}"
        )


def test_covers_all_severity_levels(scan_result):
    """Fixtures must produce findings at all five severity levels."""
    found_severities = {f.severity.value for f in scan_result.findings}
    for sev in VALID_SEVERITIES:
        assert sev in found_severities, f"No findings at severity '{sev}' — check fixtures"


def test_no_boto3_in_simulated_provider():
    """SimulatedScannerProvider must not actually import boto3.

    The docstring mentions 'Does NOT import boto3' — so we check for
    actual top-level import statements using AST parsing, not string search.
    """
    import ast
    import inspect
    import providers.simulated as sim_mod
    source = inspect.getsource(sim_mod)
    tree = ast.parse(source)
    boto3_imports = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and any(
            (isinstance(node, ast.Import) and alias.name == "boto3")
            or (isinstance(node, ast.ImportFrom) and node.module == "boto3")
            for alias in (node.names if isinstance(node, ast.Import) else node.names)
        )
    ]
    assert boto3_imports == [], (
        "SimulatedScannerProvider must not import boto3. "
        "It should load data from JSON fixtures only."
    )


def test_scanner_accepts_region(scan_result):
    """Scanner accepts a region parameter and stores it in the result."""
    provider = SimulatedScannerProvider()
    scanner = Scanner(provider)
    result = scanner.run(region="eu-west-1")
    assert result.region == "eu-west-1"


def test_scan_result_has_scan_id(scan_result):
    """ScanResult must have a non-empty scan_id."""
    assert scan_result.scan_id
    assert len(scan_result.scan_id) == 36  # UUID4 format


def test_scan_result_has_timestamp(scan_result):
    """ScanResult must have a non-empty ISO timestamp."""
    assert scan_result.timestamp
    assert "T" in scan_result.timestamp  # ISO 8601 format
