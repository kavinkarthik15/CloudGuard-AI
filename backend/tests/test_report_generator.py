"""
Tests for JSON and CSV report generation.
"""
import csv
import io
import json
from datetime import datetime, timezone

import pytest

from models import Finding, ScanResult, Severity, Warning
from report_generator import generate_csv_report, generate_json_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(n_findings: int = 3) -> ScanResult:
    findings = [
        Finding(
            resource_type="S3Bucket",
            resource_name=f"test-bucket-{i}",
            severity=Severity.Critical if i == 0 else Severity.High,
            title=f"Test finding {i}",
            evidence={"key": f"value-{i}"},
            risk_explanation=f"Risk explanation {i}. This finding is based on simulated configuration data.",
            remediation=f"Fix it by doing step {i}.\nAnd step {i+1}.",
        )
        for i in range(n_findings)
    ]
    return ScanResult(
        timestamp=datetime.now(timezone.utc).isoformat(),
        simulated=True,
        region="us-east-1",
        findings=findings,
        warnings=[],
        summary={"Critical": 1, "High": n_findings - 1, "Medium": 0, "Low": 0, "Informational": 0},
    )


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def test_json_export_contains_simulated_true():
    result = _make_result()
    data = json.loads(generate_json_report(result))
    assert data["simulated"] is True


def test_json_export_has_all_finding_fields():
    result = _make_result()
    data = json.loads(generate_json_report(result))
    for finding in data["findings"]:
        for field in ("resource_type", "resource_name", "severity", "title",
                      "evidence", "risk_explanation", "remediation"):
            assert field in finding, f"Missing field: {field}"


def test_json_export_finding_count():
    result = _make_result(5)
    data = json.loads(generate_json_report(result))
    assert len(data["findings"]) == 5


def test_json_export_has_scan_id_and_timestamp():
    result = _make_result()
    data = json.loads(generate_json_report(result))
    assert "scan_id" in data
    assert "timestamp" in data


def test_json_export_returns_bytes():
    result = _make_result()
    output = generate_json_report(result)
    assert isinstance(output, bytes)


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def test_csv_export_has_header():
    result = _make_result(3)
    content = generate_csv_report(result).decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    assert "simulated" in reader.fieldnames
    assert "resource_type" in reader.fieldnames
    assert "severity" in reader.fieldnames
    assert "title" in reader.fieldnames


def test_csv_export_one_row_per_finding():
    result = _make_result(4)
    content = generate_csv_report(result).decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(content)))
    assert len(rows) == 4


def test_csv_export_simulated_column_true():
    result = _make_result(3)
    content = generate_csv_report(result).decode("utf-8")
    for row in csv.DictReader(io.StringIO(content)):
        assert row["simulated"] == "true"


def test_csv_export_no_embedded_newlines():
    """Multi-line remediation text must not produce embedded newlines in CSV rows."""
    result = _make_result(2)
    content = generate_csv_report(result).decode("utf-8")
    for row in csv.DictReader(io.StringIO(content)):
        for field, value in row.items():
            assert "\n" not in value, f"Field '{field}' contains embedded newline"


def test_csv_export_returns_bytes():
    result = _make_result()
    output = generate_csv_report(result)
    assert isinstance(output, bytes)


def test_csv_export_empty_findings():
    result = _make_result(0)
    content = generate_csv_report(result).decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(content)))
    assert rows == []
