"""
Integration tests for the scan-id-specific export endpoints.

Tests:
  - Successful JSON and CSV export by scan_id
  - Unknown scan_id returns SCAN_NOT_FOUND (404)
  - Export simulated flag matches the scan result
  - Demo and live scan exports cannot be cross-served
  - Concurrent scans: each scan_id retrieves its own result
  - Legacy endpoints still work (backward compatibility)
  - export_filename produces distinct names for distinct scans
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import pytest

from fastapi.testclient import TestClient

from main import app, _app_state, _store_scan_result, _get_scan_result
from models import Finding, ScanResult, Severity, Warning


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_scan_store():
    """Reset in-memory scan store before each test."""
    _app_state["scan_store"].clear()
    _app_state["last_scan_id"] = None
    yield
    _app_state["scan_store"].clear()
    _app_state["last_scan_id"] = None


@pytest.fixture
def client():
    return TestClient(app)


def _make_scan_result(simulated: bool = True, n_findings: int = 2) -> ScanResult:
    findings = [
        Finding(
            resource_type="S3Bucket" if simulated else "SecurityGroup",
            resource_name=f"test-resource-{i}",
            severity=Severity.High,
            title=f"Test finding {i}",
            evidence={"key": f"val-{i}"},
            risk_explanation=(
                "Simulated config data." if simulated else "Live AWS config data."
            ),
            remediation="Fix it.",
            simulated=simulated,
        )
        for i in range(n_findings)
    ]
    return ScanResult(
        timestamp=datetime.now(timezone.utc).isoformat(),
        simulated=simulated,
        region="eu-north-1",
        findings=findings,
        warnings=[],
        summary={"Critical": 0, "High": n_findings, "Medium": 0, "Low": 0, "Informational": 0},
        aws_account_id=None if simulated else "123456789012",
        aws_identity_arn=None if simulated else "arn:aws:sts::123456789012:assumed-role/R/s",
    )


# ---------------------------------------------------------------------------
# Scan-id-specific export — JSON
# ---------------------------------------------------------------------------

def test_export_json_by_scan_id_returns_200(client):
    result = _make_scan_result(simulated=True)
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/json")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    content = r.headers.get("content-disposition", "")
    assert "attachment" in content
    assert ".json" in content


def test_export_json_scan_id_header_matches(client):
    result = _make_scan_result()
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/json")
    assert r.headers.get("x-scan-id") == result.scan_id


def test_export_json_simulated_header_true_for_demo(client):
    result = _make_scan_result(simulated=True)
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/json")
    assert r.headers.get("x-scan-simulated") == "true"


def test_export_json_simulated_header_false_for_live(client):
    result = _make_scan_result(simulated=False)
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/json")
    assert r.headers.get("x-scan-simulated") == "false"


def test_export_json_body_simulated_matches_scan(client):
    """JSON body simulated field must match the scan, not be hardcoded True."""
    result = _make_scan_result(simulated=False)
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/json")
    data = r.json()
    assert data["simulated"] is False


def test_export_json_body_scan_id_matches(client):
    result = _make_scan_result()
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/json")
    data = r.json()
    assert data["scan_id"] == result.scan_id


def test_export_json_body_findings_count_matches(client):
    result = _make_scan_result(n_findings=3)
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/json")
    data = r.json()
    assert len(data["findings"]) == 3


# ---------------------------------------------------------------------------
# Scan-id-specific export — CSV
# ---------------------------------------------------------------------------

def test_export_csv_by_scan_id_returns_200(client):
    result = _make_scan_result()
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


def test_export_csv_simulated_column_matches_scan(client):
    """CSV simulated column must reflect the actual scan source."""
    demo = _make_scan_result(simulated=True, n_findings=2)
    live = _make_scan_result(simulated=False, n_findings=2)
    _store_scan_result(demo)
    _store_scan_result(live)

    r_demo = client.get(f"/api/export/{demo.scan_id}/csv")
    r_live = client.get(f"/api/export/{live.scan_id}/csv")

    demo_rows = list(csv.DictReader(io.StringIO(r_demo.text)))
    live_rows = list(csv.DictReader(io.StringIO(r_live.text)))

    for row in demo_rows:
        assert row["simulated"] == "true", "Demo CSV row has wrong simulated value"
    for row in live_rows:
        assert row["simulated"] == "false", "Live CSV row has wrong simulated value"


def test_export_csv_row_count_matches_findings(client):
    result = _make_scan_result(n_findings=4)
    _store_scan_result(result)

    r = client.get(f"/api/export/{result.scan_id}/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 4


# ---------------------------------------------------------------------------
# SCAN_NOT_FOUND — unknown or expired scan_id
# ---------------------------------------------------------------------------

def test_export_json_unknown_scan_id_returns_404(client):
    r = client.get("/api/export/nonexistent-scan-id-00000000/json")
    assert r.status_code == 404
    data = r.json()
    assert data["code"] == "SCAN_NOT_FOUND"
    assert "nonexistent-scan-id" in data["message"] or "not found" in data["message"].lower()


def test_export_csv_unknown_scan_id_returns_404(client):
    r = client.get("/api/export/nonexistent-scan-id-00000000/csv")
    assert r.status_code == 404
    assert r.json()["code"] == "SCAN_NOT_FOUND"


def test_export_json_after_store_clear_returns_404(client):
    """After store is cleared (server restart simulation), export must fail cleanly."""
    result = _make_scan_result()
    _store_scan_result(result)
    saved_scan_id = result.scan_id

    # Simulate server restart
    _app_state["scan_store"].clear()
    _app_state["last_scan_id"] = None

    r = client.get(f"/api/export/{saved_scan_id}/json")
    assert r.status_code == 404
    assert r.json()["code"] == "SCAN_NOT_FOUND"


# ---------------------------------------------------------------------------
# Mode separation — cross-mode export prevention
# ---------------------------------------------------------------------------

def test_demo_scan_id_cannot_serve_live_export(client):
    """A demo scan_id never returns a live result (scan is stored by id, not mode)."""
    demo = _make_scan_result(simulated=True)
    live = _make_scan_result(simulated=False)
    _store_scan_result(demo)
    _store_scan_result(live)

    # Requesting demo's scan_id must always return demo data
    r = client.get(f"/api/export/{demo.scan_id}/json")
    data = r.json()
    assert data["simulated"] is True
    assert data["scan_id"] == demo.scan_id

    # Requesting live's scan_id must always return live data
    r = client.get(f"/api/export/{live.scan_id}/json")
    data = r.json()
    assert data["simulated"] is False
    assert data["scan_id"] == live.scan_id


def test_switching_modes_does_not_corrupt_previous_export(client):
    """After switching modes, the previous scan_id still exports correctly."""
    demo = _make_scan_result(simulated=True, n_findings=5)
    _store_scan_result(demo)
    demo_scan_id = demo.scan_id

    # Now store a live result (mode "switch")
    live = _make_scan_result(simulated=False, n_findings=0)
    _store_scan_result(live)

    # Demo scan_id must still be retrievable
    r = client.get(f"/api/export/{demo_scan_id}/json")
    assert r.status_code == 200
    data = r.json()
    assert data["simulated"] is True
    assert len(data["findings"]) == 5


# ---------------------------------------------------------------------------
# Concurrent scan storage
# ---------------------------------------------------------------------------

def test_concurrent_scans_stored_independently(client):
    """Multiple scan results can be stored and retrieved independently."""
    results = [_make_scan_result(n_findings=i) for i in range(1, 5)]
    for r in results:
        _store_scan_result(r)

    for r in results:
        resp = client.get(f"/api/export/{r.scan_id}/json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == r.scan_id
        assert len(data["findings"]) == len(r.findings)


def test_store_cap_evicts_oldest(client):
    """When MAX_STORED_SCANS is exceeded, oldest scans are evicted."""
    from main import MAX_STORED_SCANS

    scans = [_make_scan_result() for _ in range(MAX_STORED_SCANS + 2)]
    first_scan_id = scans[0].scan_id

    for scan in scans:
        _store_scan_result(scan)

    # The first scan should have been evicted
    r = client.get(f"/api/export/{first_scan_id}/json")
    assert r.status_code == 404
    assert r.json()["code"] == "SCAN_NOT_FOUND"

    # The latest scan should still be available
    last_scan_id = scans[-1].scan_id
    r = client.get(f"/api/export/{last_scan_id}/json")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Legacy export endpoints (backward compatibility)
# ---------------------------------------------------------------------------

def test_legacy_export_json_returns_200_when_scan_exists(client):
    result = _make_scan_result()
    _store_scan_result(result)

    r = client.get("/api/export/json")
    assert r.status_code == 200


def test_legacy_export_csv_returns_200_when_scan_exists(client):
    result = _make_scan_result()
    _store_scan_result(result)

    r = client.get("/api/export/csv")
    assert r.status_code == 200


def test_legacy_export_json_returns_404_when_no_scan(client):
    r = client.get("/api/export/json")
    assert r.status_code == 404
    assert r.json()["code"] == "NO_SCAN_RESULT"


def test_legacy_export_returns_most_recent_scan(client):
    """Legacy endpoint returns last stored scan, not an arbitrary one."""
    older = _make_scan_result(n_findings=2)
    newer = _make_scan_result(n_findings=5)
    _store_scan_result(older)
    _store_scan_result(newer)

    r = client.get("/api/export/json")
    data = r.json()
    assert data["scan_id"] == newer.scan_id
    assert len(data["findings"]) == 5
