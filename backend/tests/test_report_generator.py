"""
Tests for JSON and CSV report generation.
Covers both simulated (demo) and live scan results.
"""
import csv
import io
import json
from datetime import datetime, timezone

import pytest

from models import Finding, ScanResult, Severity, Warning
from report_generator import export_filename, generate_csv_report, generate_json_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(n_findings: int = 3, simulated: bool = True) -> ScanResult:
    findings = [
        Finding(
            resource_type="S3Bucket",
            resource_name=f"test-bucket-{i}",
            severity=Severity.Critical if i == 0 else Severity.High,
            title=f"Test finding {i}",
            evidence={"key": f"value-{i}"},
            risk_explanation=(
                f"Risk explanation {i}. "
                + ("This finding is based on simulated configuration data."
                   if simulated
                   else "This finding is based on live AWS configuration data.")
            ),
            remediation=f"Fix it by doing step {i}.\nAnd step {i+1}.",
            simulated=simulated,
        )
        for i in range(n_findings)
    ]
    return ScanResult(
        timestamp=datetime.now(timezone.utc).isoformat(),
        simulated=simulated,
        region="us-east-1",
        findings=findings,
        warnings=[],
        summary={"Critical": 1, "High": max(n_findings - 1, 0), "Medium": 0, "Low": 0, "Informational": 0},
        aws_account_id=None if simulated else "123456789012",
        aws_identity_arn=None if simulated else "arn:aws:sts::123456789012:assumed-role/TestRole/session",
    )


# ---------------------------------------------------------------------------
# JSON export — simulated scan
# ---------------------------------------------------------------------------

def test_json_export_contains_simulated_true():
    result = _make_result(simulated=True)
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
# JSON export — live scan
# ---------------------------------------------------------------------------

def test_json_export_live_scan_has_simulated_false():
    """Live scan exports must have simulated=False, not hardcoded True."""
    result = _make_result(simulated=False)
    data = json.loads(generate_json_report(result))
    assert data["simulated"] is False, "Live scan export must not report simulated=True"


def test_json_export_live_scan_includes_account_id():
    result = _make_result(simulated=False)
    data = json.loads(generate_json_report(result))
    assert data.get("aws_account_id") == "123456789012"


def test_json_export_live_scan_finding_has_simulated_false():
    result = _make_result(simulated=False)
    data = json.loads(generate_json_report(result))
    for finding in data["findings"]:
        assert finding["simulated"] is False, (
            f"Finding '{finding['title']}' has simulated=True in a live export"
        )


def test_json_export_scan_id_matches_result():
    """Exported scan_id must match the ScanResult.scan_id."""
    result = _make_result()
    data = json.loads(generate_json_report(result))
    assert data["scan_id"] == result.scan_id


# ---------------------------------------------------------------------------
# CSV export — simulated scan
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
    result = _make_result(3, simulated=True)
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


# ---------------------------------------------------------------------------
# CSV export — live scan
# ---------------------------------------------------------------------------

def test_csv_export_live_scan_has_simulated_false():
    """Live scan CSV must have simulated=false, not hardcoded true."""
    result = _make_result(3, simulated=False)
    content = generate_csv_report(result).decode("utf-8")
    for row in csv.DictReader(io.StringIO(content)):
        assert row["simulated"] == "false", (
            f"Live scan CSV row has simulated='{row['simulated']}', expected 'false'"
        )


# ---------------------------------------------------------------------------
# export_filename
# ---------------------------------------------------------------------------

def test_export_filename_includes_scan_id_prefix():
    """Filename must include a short scan_id prefix for distinguishability."""
    result = _make_result()
    fname = export_filename(result.scan_id, "json")
    short_id = result.scan_id[:8]
    assert short_id in fname, f"scan_id prefix '{short_id}' not found in '{fname}'"
    assert fname.endswith(".json")


def test_export_filename_csv():
    result = _make_result()
    fname = export_filename(result.scan_id, "csv")
    assert fname.endswith(".csv")


def test_export_filename_different_scans_differ():
    """Two different scans must produce different filenames."""
    r1 = _make_result()
    r2 = _make_result()
    # Different scan_ids → different short prefixes → different filenames
    assert export_filename(r1.scan_id, "json") != export_filename(r2.scan_id, "json")


# ---------------------------------------------------------------------------
# Mode separation — export must reflect correct source
# ---------------------------------------------------------------------------

def test_demo_and_live_exports_are_distinct():
    """JSON exports from demo and live scans must have different simulated values."""
    demo = _make_result(3, simulated=True)
    live = _make_result(3, simulated=False)

    demo_data = json.loads(generate_json_report(demo))
    live_data = json.loads(generate_json_report(live))

    assert demo_data["simulated"] is True
    assert live_data["simulated"] is False
    # Scan IDs must differ
    assert demo_data["scan_id"] != live_data["scan_id"]
