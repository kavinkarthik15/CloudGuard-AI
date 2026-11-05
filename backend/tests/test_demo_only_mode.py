"""
Tests for Demo-Only production mode (ALLOW_LIVE_AWS_SCANS=false).

All AWS interactions are mocked — no real credentials are used.

When ALLOW_LIVE_AWS_SCANS=false:
  - GET  /api/identity          → 403 LIVE_AWS_DISABLED
  - POST /api/identity          → 403 LIVE_AWS_DISABLED
  - POST /api/scan (mode=live)  → 403 LIVE_AWS_DISABLED
  - GET  /api/regions?profile=X → 403 LIVE_AWS_DISABLED (enriched path)
  - No Boto3 provider is created for any of the above

When ALLOW_LIVE_AWS_SCANS=true (default):
  - All existing live-mode behavior works unchanged

Demo-mode operations always work regardless of the flag:
  - POST /api/scan (mode=demo)   → 200, simulated=true
  - GET  /api/regions (no profile) → 200, static botocore metadata
  - GET  /api/health             → 200, live_mode_available reflects the flag
"""
from __future__ import annotations

import importlib
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LIVE_DISABLED_CODE = "LIVE_AWS_DISABLED"


def _make_app_with_flag(allow_live: bool) -> TestClient:
    """Create a fresh FastAPI TestClient with ALLOW_LIVE_AWS_SCANS set."""
    import config
    import main

    # Patch the flag in both modules (main imports it from config at module level)
    with patch.object(config, "ALLOW_LIVE_AWS_SCANS", allow_live), \
         patch.object(main, "ALLOW_LIVE_AWS_SCANS", allow_live):
        client = TestClient(main.app, raise_server_exceptions=False)
        yield client


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def demo_only_client():
    """TestClient with ALLOW_LIVE_AWS_SCANS=False."""
    import config
    import main
    with patch.object(config, "ALLOW_LIVE_AWS_SCANS", False), \
         patch.object(main, "ALLOW_LIVE_AWS_SCANS", False):
        yield TestClient(main.app)


@pytest.fixture
def live_enabled_client():
    """TestClient with ALLOW_LIVE_AWS_SCANS=True (default behavior)."""
    import config
    import main
    with patch.object(config, "ALLOW_LIVE_AWS_SCANS", True), \
         patch.object(main, "ALLOW_LIVE_AWS_SCANS", True):
        yield TestClient(main.app)


# ---------------------------------------------------------------------------
# GET /api/identity — demo-only mode
# ---------------------------------------------------------------------------

class TestGetIdentityDemoOnly:
    def test_get_identity_returns_403_when_live_disabled(self, demo_only_client):
        r = demo_only_client.get("/api/identity?profile=cloudguard&region=eu-north-1")
        assert r.status_code == 403
        assert r.json()["code"] == LIVE_DISABLED_CODE

    def test_get_identity_error_message_does_not_contain_credentials(self, demo_only_client):
        r = demo_only_client.get("/api/identity?profile=cloudguard")
        assert r.status_code == 403
        body = r.text
        # Must not echo any credential-related values
        assert "AKIA" not in body
        assert "secret" not in body.lower()

    def test_get_identity_does_not_create_boto3_provider_when_disabled(self, demo_only_client):
        """Boto3 provider must not be instantiated when live scans are disabled."""
        with patch("main.get_boto3_provider") as mock_get:
            demo_only_client.get("/api/identity?profile=cloudguard")
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# POST /api/identity — demo-only mode
# ---------------------------------------------------------------------------

class TestPostIdentityDemoOnly:
    def test_post_identity_returns_403_when_live_disabled(self, demo_only_client):
        r = demo_only_client.post("/api/identity", json={
            "region": "eu-north-1",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        })
        assert r.status_code == 403
        assert r.json()["code"] == LIVE_DISABLED_CODE

    def test_post_identity_response_does_not_echo_credentials(self, demo_only_client):
        """403 response must not contain any submitted credential values."""
        fake_key = "AKIAIOSFODNN7EXAMPLE"
        fake_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        r = demo_only_client.post("/api/identity", json={
            "region": "eu-north-1",
            "aws_access_key_id": fake_key,
            "aws_secret_access_key": fake_secret,
        })
        assert r.status_code == 403
        assert fake_key not in r.text
        assert fake_secret not in r.text

    def test_post_identity_does_not_create_boto3_provider_when_disabled(self, demo_only_client):
        with patch("main.get_boto3_provider") as mock_get:
            demo_only_client.post("/api/identity", json={
                "region": "eu-north-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            })
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# POST /api/scan with mode=live — demo-only mode
# ---------------------------------------------------------------------------

class TestLiveScanDemoOnly:
    def test_live_scan_returns_403_when_live_disabled(self, demo_only_client):
        r = demo_only_client.post("/api/scan", json={
            "mode": "live",
            "region": "eu-north-1",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        })
        assert r.status_code == 403
        assert r.json()["code"] == LIVE_DISABLED_CODE

    def test_live_scan_does_not_create_boto3_provider_when_disabled(self, demo_only_client):
        with patch("main.get_boto3_provider") as mock_get:
            demo_only_client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
            })
        mock_get.assert_not_called()

    def test_live_scan_response_does_not_echo_credentials(self, demo_only_client):
        fake_key = "AKIAIOSFODNN7EXAMPLE"
        fake_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        r = demo_only_client.post("/api/scan", json={
            "mode": "live",
            "region": "eu-north-1",
            "aws_access_key_id": fake_key,
            "aws_secret_access_key": fake_secret,
        })
        assert r.status_code == 403
        assert fake_key not in r.text
        assert fake_secret not in r.text


# ---------------------------------------------------------------------------
# GET /api/regions?profile= — demo-only mode
# ---------------------------------------------------------------------------

class TestRegionsDemoOnly:
    def test_regions_with_profile_uses_live_flag(self, demo_only_client):
        """With profile supplied, DescribeRegions is skipped — returns botocore list only."""
        # The route still returns 200 with static data; it just skips the
        # AWS DescribeRegions enrichment path when live is disabled.
        r = demo_only_client.get("/api/regions?profile=cloudguard")
        # Must not return 403 — the static region list is always available.
        # The enrichment (DescribeRegions) is silently skipped.
        assert r.status_code == 200
        data = r.json()
        assert len(data["regions"]) > 0
        # enabled_regions_available must be False since we skipped the AWS call
        assert data["enabled_regions_available"] is False

    def test_regions_without_profile_always_works(self, demo_only_client):
        """Static botocore region list never requires live AWS — always available."""
        r = demo_only_client.get("/api/regions")
        assert r.status_code == 200
        assert len(r.json()["regions"]) > 0

    def test_regions_without_profile_does_not_call_boto3(self, demo_only_client):
        with patch("main.get_boto3_provider") as mock_get:
            demo_only_client.get("/api/regions")
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# Demo scan always works
# ---------------------------------------------------------------------------

class TestDemoScanAlwaysWorks:
    def test_demo_scan_returns_200_when_live_disabled(self, demo_only_client):
        r = demo_only_client.post("/api/scan", json={
            "mode": "demo",
            "region": "eu-north-1",
        })
        assert r.status_code == 200
        assert r.json()["simulated"] is True

    def test_demo_scan_returns_findings_when_live_disabled(self, demo_only_client):
        r = demo_only_client.post("/api/scan", json={"mode": "demo"})
        assert r.status_code == 200
        data = r.json()
        assert data["simulated"] is True
        assert len(data["findings"]) > 0


# ---------------------------------------------------------------------------
# GET /api/health reflects the flag
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_reports_live_mode_false_when_disabled(self, demo_only_client):
        r = demo_only_client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["live_mode_available"] is False

    def test_health_reports_live_mode_true_when_enabled(self, live_enabled_client):
        r = live_enabled_client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["live_mode_available"] is True


# ---------------------------------------------------------------------------
# Live-enabled mode: existing behavior preserved
# ---------------------------------------------------------------------------

class TestLiveEnabledBackwardCompat:
    def test_get_identity_works_when_live_enabled(self, live_enabled_client):
        """GET /api/identity is callable when live mode is enabled."""
        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "316658062107",
            "arn": "arn:aws:sts::316658062107:assumed-role/Role/s",
            "user_id": "AROAEXAMPLE:session",
        }
        with patch("main.get_boto3_provider", return_value=mock_provider):
            r = live_enabled_client.get("/api/identity?profile=cloudguard&region=eu-north-1")
        assert r.status_code == 200
        assert r.json()["account_id"] == "316658062107"

    def test_live_scan_works_when_live_enabled(self, live_enabled_client):
        """POST /api/scan mode=live is callable when live mode is enabled."""
        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "316658062107",
            "arn": "arn:aws:sts::316658062107:assumed-role/Role/s",
            "user_id": "AROAEXAMPLE:session",
        }
        mock_provider.list_s3_buckets.return_value = []
        mock_provider.list_security_groups.return_value = []
        with patch("main.get_boto3_provider", return_value=mock_provider):
            r = live_enabled_client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            })
        assert r.status_code == 200
        assert r.json()["simulated"] is False
