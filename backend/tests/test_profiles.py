"""
Tests for Phase 4A — AWS profile discovery, validation, and the
GET /api/profiles endpoint.

All tests use mocked botocore/boto3 — no real AWS calls are made.
No credential values are exposed in assertions.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from main import app, _app_state
from providers.boto3_provider import (
    ProfileDiscoveryError,
    _validate_profile_name,
    list_available_profiles,
)


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# list_available_profiles()
# ---------------------------------------------------------------------------

def test_list_profiles_returns_names_only():
    """Profiles response contains only string names, no credentials."""
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_session = MagicMock()
        mock_session.available_profiles = ["default", "cloudguard", "staging"]
        mock_bc.session.Session.return_value = mock_session
        profiles = list_available_profiles()

    assert all(isinstance(p, str) for p in profiles)
    assert "default" in profiles
    assert "cloudguard" in profiles
    # Ensure no credential-looking values leaked in
    for p in profiles:
        assert not p.startswith("AKIA")
        assert "secret" not in p.lower()
        assert "password" not in p.lower()


def test_list_profiles_empty_config():
    """No profiles configured → returns empty list, does not raise."""
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_session = MagicMock()
        mock_session.available_profiles = []
        mock_bc.session.Session.return_value = mock_session
        profiles = list_available_profiles()

    assert profiles == []


def test_list_profiles_raises_on_config_error():
    """Unreadable configuration → ProfileDiscoveryError."""
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_bc.session.Session.side_effect = PermissionError("Permission denied")
        with pytest.raises(ProfileDiscoveryError) as exc_info:
            list_available_profiles()

    assert "Could not read AWS configuration" in str(exc_info.value)


def test_list_profiles_does_not_execute_credential_helpers():
    """Profile discovery must not call get_credentials() or boto3.Session().

    External credential helpers are invoked by boto3 when credentials are
    resolved, not during profile listing. This test verifies that
    list_available_profiles() only calls botocore.session.Session().available_profiles
    and does NOT call boto3.Session() or any credential resolution method.
    """
    with patch("providers.boto3_provider.botocore") as mock_bc, \
         patch("providers.boto3_provider.boto3") as mock_boto3:
        mock_bcore_session = MagicMock()
        mock_bcore_session.available_profiles = ["test-profile"]
        mock_bc.session.Session.return_value = mock_bcore_session

        result = list_available_profiles()

        # boto3.Session must NOT be called during profile discovery
        mock_boto3.Session.assert_not_called()
        # get_credentials must NOT be called during profile discovery
        mock_bcore_session.get_credentials.assert_not_called()

    assert result == ["test-profile"]


# ---------------------------------------------------------------------------
# _validate_profile_name()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "default",
    "cloudguard",
    "my-profile",
    "prod_account",
    "My Profile",           # spaces are valid in AWS CLI profile names
    "account.123",
    "us-east-prod",
])
def test_validate_profile_name_accepts_valid_names(name: str):
    """Valid profile names are accepted without raising."""
    _validate_profile_name(name)  # should not raise


@pytest.mark.parametrize("name,expected_fragment", [
    ("", "empty"),
    ("   ", "empty"),
    ("a\x00b", "null"),
    ("../etc/passwd", "traversal"),
    ("../../root", "traversal"),
    ("/etc/passwd", "absolute"),
    ("\\windows", "absolute"),
    ("C:\\Users", "absolute"),
    ("a;b", "disallowed"),
    ("a|b", "disallowed"),
    ("a`b", "disallowed"),
    ("a$b", "disallowed"),
    ("a&&b", "disallowed"),
    ("a>b", "disallowed"),
    ("a<b", "disallowed"),
    ("a" * 513, "long"),
])
def test_validate_profile_name_rejects_dangerous_input(name: str, expected_fragment: str):
    """Dangerous or malformed profile names are rejected with a descriptive error."""
    with pytest.raises(ValueError) as exc_info:
        _validate_profile_name(name)
    # The error message should be informative (but not repeat the bad input verbatim)
    assert len(str(exc_info.value)) > 0


def test_validate_profile_name_dotdot_alone():
    """'..' alone is rejected as a path traversal attempt."""
    with pytest.raises(ValueError):
        _validate_profile_name("..")


def test_validate_profile_name_path_with_slash():
    """A path-like name with slashes is rejected."""
    with pytest.raises(ValueError):
        _validate_profile_name("profiles/prod")


# ---------------------------------------------------------------------------
# GET /api/profiles endpoint
# ---------------------------------------------------------------------------

def test_get_profiles_returns_200(client):
    """Endpoint returns 200 with a ProfilesResponse body."""
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_session = MagicMock()
        mock_session.available_profiles = ["default", "cloudguard"]
        mock_bc.session.Session.return_value = mock_session

        r = client.get("/api/profiles")

    assert r.status_code == 200
    data = r.json()
    assert "profiles" in data
    assert "default" in data["profiles"]
    assert "cloudguard" in data["profiles"]


def test_get_profiles_response_contains_no_credentials(client):
    """Profile names in response must not look like credentials."""
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_session = MagicMock()
        mock_session.available_profiles = ["default", "staging"]
        mock_bc.session.Session.return_value = mock_session

        r = client.get("/api/profiles")

    data = r.json()
    for profile in data.get("profiles", []):
        assert not profile.startswith("AKIA")
        assert not profile.startswith("ASIA")
        assert "secret" not in profile.lower()


def test_get_profiles_empty_config_returns_empty_list(client):
    """No profiles configured → empty list, discovery_error None, 200 OK."""
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_session = MagicMock()
        mock_session.available_profiles = []
        mock_bc.session.Session.return_value = mock_session

        r = client.get("/api/profiles")

    assert r.status_code == 200
    data = r.json()
    assert data["profiles"] == []
    assert data["discovery_error"] is None


def test_get_profiles_config_error_returns_error_field(client):
    """Unreadable config → 200 with discovery_error set, not 500."""
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_bc.session.Session.side_effect = PermissionError("Permission denied")

        r = client.get("/api/profiles")

    assert r.status_code == 200
    data = r.json()
    assert data["profiles"] == []
    assert data["discovery_error"] is not None
    assert len(data["discovery_error"]) > 0


def test_get_profiles_default_profile_reflects_env_var(client, monkeypatch):
    """default_profile in response mirrors the AWS_PROFILE env var."""
    monkeypatch.setenv("AWS_PROFILE", "my-org-profile")
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_session = MagicMock()
        mock_session.available_profiles = ["my-org-profile", "default"]
        mock_bc.session.Session.return_value = mock_session

        r = client.get("/api/profiles")

    data = r.json()
    assert data["default_profile"] == "my-org-profile"


def test_get_profiles_default_profile_none_when_env_unset(client, monkeypatch):
    """default_profile is None when AWS_PROFILE is not set."""
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_session = MagicMock()
        mock_session.available_profiles = ["cloudguard"]
        mock_bc.session.Session.return_value = mock_session

        r = client.get("/api/profiles")

    data = r.json()
    assert data["default_profile"] is None


def test_get_profiles_does_not_expose_file_paths(client):
    """Profile names in response must not look like file paths."""
    with patch("providers.boto3_provider.botocore") as mock_bc:
        mock_session = MagicMock()
        mock_session.available_profiles = ["default", "prod"]
        mock_bc.session.Session.return_value = mock_session

        r = client.get("/api/profiles")

    data = r.json()
    for profile in data.get("profiles", []):
        assert not profile.startswith("/")
        assert not profile.startswith("\\")
        assert ".." not in profile


# ---------------------------------------------------------------------------
# Integration: profile validation in identity endpoint
# ---------------------------------------------------------------------------

def test_identity_endpoint_rejects_traversal_profile(client):
    """GET /api/identity with a path-traversal profile name returns 400 INVALID_PROFILE.

    Malformed or unsafe profile names are rejected before an AWS session is created.
    This is deliberately distinct from NO_CREDENTIALS (profile well-formed but not
    configured) and SESSION_EXPIRED (profile found but SSO session is stale).
    """
    r = client.get("/api/identity?profile=../etc/passwd&region=us-east-1")
    assert r.status_code == 400
    data = r.json()
    assert data["code"] == "INVALID_PROFILE"


def test_identity_endpoint_rejects_shell_injection_profile(client):
    """GET /api/identity with a shell injection profile returns 400 INVALID_PROFILE."""
    r = client.get("/api/identity", params={"profile": "; rm -rf /", "region": "us-east-1"})
    assert r.status_code == 400
    assert r.json()["code"] == "INVALID_PROFILE"


# ---------------------------------------------------------------------------
# Regression: demo mode still returns 52 findings after profile changes
# ---------------------------------------------------------------------------

def test_demo_mode_unaffected_by_profile_changes(client):
    """Demo scan returns 52 findings regardless of profile configuration."""
    r = client.post("/api/scan", json={"mode": "demo", "region": "us-east-1"})
    assert r.status_code == 200
    data = r.json()
    assert data["simulated"] is True
    assert len(data["findings"]) == 52
    assert data["aws_account_id"] is None
