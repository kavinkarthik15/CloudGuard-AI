"""
Tests for explicit AWS credential authentication.

All tests are MOCKED — no real AWS credentials or API calls are used.

Coverage:
  - Valid explicit credentials create a boto3 Session with explicit args
  - Missing access key ID raises MissingCredentialsError
  - Missing secret key raises MissingCredentialsError
  - Optional session token is forwarded when present
  - Session token is omitted (None) when not supplied
  - Invalid credentials (ExpiredToken) raise SessionExpiredError
  - AccessDenied on STS raises InsufficientPermissionsError
  - No fallback to default AWS credential chain with explicit creds
  - Credential values do not appear in exception messages
  - POST /api/identity accepts explicit credentials in request body
  - POST /api/scan accepts explicit credentials
  - Existing profile-based scan still works (backward compat)
"""
from __future__ import annotations

import pytest
import botocore.exceptions
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from main import app, _app_state
from providers.boto3_provider import (
    Boto3ScannerProvider,
    MissingCredentialsError,
    SessionExpiredError,
    InsufficientPermissionsError,
    InvalidProfileError,
)

client = TestClient(app)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_scan_store():
    _app_state["scan_store"].clear()
    _app_state["last_scan_id"] = None
    yield
    _app_state["scan_store"].clear()
    _app_state["last_scan_id"] = None


def _make_client_error(code: str, msg: str = "test") -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": msg}},
        "TestOperation",
    )


# ---------------------------------------------------------------------------
# Provider unit tests: session creation
# ---------------------------------------------------------------------------

class TestExplicitSessionCreation:

    def test_explicit_creds_create_session_with_explicit_args(self):
        """boto3.Session called with explicit key/secret, NOT with profile_name."""
        with patch("providers.boto3_provider.boto3.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = MagicMock()
            mock_session_cls.return_value = mock_session

            Boto3ScannerProvider(
                profile_name="default",
                region="eu-north-1",
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            )

        # Must be called with explicit credential args
        call_kwargs = mock_session_cls.call_args.kwargs
        assert call_kwargs.get("aws_access_key_id") == "AKIAIOSFODNN7EXAMPLE"
        assert call_kwargs.get("aws_secret_access_key") == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        # Must NOT pass profile_name when using explicit creds
        assert "profile_name" not in call_kwargs

    def test_explicit_creds_with_session_token(self):
        """Session token is forwarded when provided."""
        with patch("providers.boto3_provider.boto3.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = MagicMock()
            mock_session_cls.return_value = mock_session

            Boto3ScannerProvider(
                region="eu-north-1",
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                session_token="FwoGZXIvYXdzEJr//////////EXAMPLE_TOKEN",
            )

        call_kwargs = mock_session_cls.call_args.kwargs
        assert call_kwargs.get("aws_session_token") == "FwoGZXIvYXdzEJr//////////EXAMPLE_TOKEN"

    def test_explicit_creds_without_session_token_passes_none(self):
        """session_token=None when not supplied — never passes empty string."""
        with patch("providers.boto3_provider.boto3.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = MagicMock()
            mock_session_cls.return_value = mock_session

            Boto3ScannerProvider(
                region="eu-north-1",
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                # no session_token
            )

        call_kwargs = mock_session_cls.call_args.kwargs
        assert call_kwargs.get("aws_session_token") is None

    def test_missing_access_key_raises_missing_credentials_error(self):
        """Empty/missing access key ID raises MissingCredentialsError before any AWS call."""
        with pytest.raises(MissingCredentialsError) as exc_info:
            Boto3ScannerProvider(
                region="eu-north-1",
                access_key_id="",  # empty
                secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            )
        assert "Access Key ID" in str(exc_info.value)

    def test_missing_secret_key_raises_missing_credentials_error(self):
        """Empty/missing secret key raises MissingCredentialsError before any AWS call."""
        with pytest.raises(MissingCredentialsError) as exc_info:
            Boto3ScannerProvider(
                region="eu-north-1",
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key="",  # empty
            )
        assert "Secret" in str(exc_info.value) or "secret" in str(exc_info.value)

    def test_missing_credentials_error_does_not_contain_credential_values(self):
        """Error messages from missing credentials must not echo back secret values."""
        fake_key = "AKIAIOSFODNN7EXAMPLE"
        fake_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        try:
            Boto3ScannerProvider(
                region="eu-north-1",
                access_key_id=fake_key,
                secret_access_key="",
            )
        except MissingCredentialsError as exc:
            assert fake_key not in str(exc), "Error message must not contain key ID"
            assert fake_secret not in str(exc), "Error message must not contain secret"

    def test_no_fallback_to_default_credential_chain_with_explicit_creds(self):
        """When explicit creds are supplied, boto3.Session must not use profile_name."""
        with patch("providers.boto3_provider.boto3.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get_credentials.return_value = MagicMock()
            mock_session_cls.return_value = mock_session

            Boto3ScannerProvider(
                profile_name="cloudguard",  # profile exists but must be ignored
                region="eu-north-1",
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            )

        call_kwargs = mock_session_cls.call_args.kwargs
        # profile_name must NOT be in call kwargs when explicit creds are provided
        assert "profile_name" not in call_kwargs, (
            "Explicit credentials must not fall back to profile-based credential chain"
        )


# ---------------------------------------------------------------------------
# API endpoint tests: POST /api/identity
# ---------------------------------------------------------------------------

class TestPostIdentityEndpoint:

    def test_post_identity_with_explicit_creds_returns_200(self):
        """POST /api/identity with valid explicit credentials returns 200."""
        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "316658062107",
            "arn": "arn:aws:sts::316658062107:assumed-role/CloudGuardRole/session",
            "user_id": "AROAEXAMPLE:session",
        }

        with patch("main.get_boto3_provider", return_value=mock_provider):
            r = client.post("/api/identity", json={
                "region": "eu-north-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            })

        assert r.status_code == 200
        data = r.json()
        assert data["account_id"] == "316658062107"
        # profile field should be None for explicit creds
        assert data["profile"] is None

    def test_post_identity_response_never_contains_credentials(self):
        """Identity response must not echo back any credential values."""
        fake_key = "AKIAIOSFODNN7EXAMPLE"
        fake_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "316658062107",
            "arn": "arn:aws:sts::316658062107:assumed-role/Role/s",
            "user_id": "AROAEXAMPLE:session",
        }

        with patch("main.get_boto3_provider", return_value=mock_provider):
            r = client.post("/api/identity", json={
                "region": "eu-north-1",
                "aws_access_key_id": fake_key,
                "aws_secret_access_key": fake_secret,
            })

        response_text = r.text
        assert fake_key not in response_text, "Response must not contain access key ID"
        assert fake_secret not in response_text, "Response must not contain secret key"

    def test_post_identity_with_missing_secret_returns_401(self):
        """POST /api/identity with empty secret key returns 401 NO_CREDENTIALS."""
        # The provider raises MissingCredentialsError before any AWS call
        from providers.boto3_provider import MissingCredentialsError as MCE
        with patch("main.get_boto3_provider", side_effect=MCE("Secret key required")):
            r = client.post("/api/identity", json={
                "region": "eu-north-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "",
            })
        assert r.status_code == 401
        assert r.json()["code"] == "NO_CREDENTIALS"

    def test_post_identity_invalid_credentials_returns_401(self):
        """POST /api/identity with invalid credentials (expired token) returns 401."""
        from providers.boto3_provider import SessionExpiredError
        with patch("main.get_boto3_provider") as mock_get:
            mock_provider = MagicMock()
            mock_provider.get_caller_identity.side_effect = SessionExpiredError("Token expired")
            mock_get.return_value = mock_provider
            r = client.post("/api/identity", json={
                "region": "eu-north-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "invalid_secret",
            })
        assert r.status_code == 401
        # Error message must not echo back the invalid secret
        assert "invalid_secret" not in r.text

    def test_post_identity_access_denied_returns_403(self):
        """AccessDenied on sts:GetCallerIdentity returns 403 INSUFFICIENT_PERMISSIONS."""
        from providers.boto3_provider import InsufficientPermissionsError
        with patch("main.get_boto3_provider") as mock_get:
            mock_provider = MagicMock()
            mock_provider.get_caller_identity.side_effect = InsufficientPermissionsError("Denied")
            mock_get.return_value = mock_provider
            r = client.post("/api/identity", json={
                "region": "eu-north-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            })
        assert r.status_code == 403
        assert r.json()["code"] == "INSUFFICIENT_PERMISSIONS"

    def test_post_identity_with_optional_session_token(self):
        """POST /api/identity with session token succeeds."""
        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "316658062107",
            "arn": "arn:aws:sts::316658062107:assumed-role/Role/session",
            "user_id": "AROAEXAMPLE:session",
        }

        with patch("main.get_boto3_provider", return_value=mock_provider) as mock_get:
            r = client.post("/api/identity", json={
                "region": "eu-north-1",
                "aws_access_key_id": "ASIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_session_token": "FwoGZXIvYXdzEJr//////////EXAMPLE",
            })

        assert r.status_code == 200
        # Verify the token was forwarded to the provider factory
        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs.get("session_token") == "FwoGZXIvYXdzEJr//////////EXAMPLE"


# ---------------------------------------------------------------------------
# API endpoint tests: POST /api/scan with explicit credentials
# ---------------------------------------------------------------------------

class TestScanWithExplicitCreds:

    def test_live_scan_with_explicit_creds_returns_200(self):
        """POST /api/scan with explicit credentials runs successfully."""
        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "316658062107",
            "arn": "arn:aws:sts::316658062107:assumed-role/Role/s",
            "user_id": "AROAEXAMPLE:session",
        }
        mock_provider.list_s3_buckets.return_value = []
        mock_provider.list_security_groups.return_value = []

        with patch("main.get_boto3_provider", return_value=mock_provider):
            r = client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            })

        assert r.status_code == 200
        data = r.json()
        assert data["simulated"] is False

    def test_scan_response_never_contains_credentials(self):
        """Scan result must not contain any credential values."""
        fake_key = "AKIAIOSFODNN7EXAMPLE"
        fake_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "316658062107",
            "arn": "arn:aws:sts::316658062107:assumed-role/Role/s",
            "user_id": "AROAEXAMPLE:session",
        }
        mock_provider.list_s3_buckets.return_value = []
        mock_provider.list_security_groups.return_value = []

        with patch("main.get_boto3_provider", return_value=mock_provider):
            r = client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
                "aws_access_key_id": fake_key,
                "aws_secret_access_key": fake_secret,
            })

        assert fake_key not in r.text, "Scan response must not contain access key ID"
        assert fake_secret not in r.text, "Scan response must not contain secret key"

    def test_explicit_creds_forwarded_to_provider_factory(self):
        """Scan endpoint forwards explicit credentials to get_boto3_provider."""
        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "123456789012",
            "arn": "arn:aws:sts::123456789012:assumed-role/Role/s",
            "user_id": "AROAEXAMPLE:session",
        }
        mock_provider.list_s3_buckets.return_value = []
        mock_provider.list_security_groups.return_value = []

        with patch("main.get_boto3_provider", return_value=mock_provider) as mock_get:
            client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_session_token": "FwoGZXIvYXdzEJr//////////EXAMPLE",
            })

        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs.get("access_key_id") == "AKIAIOSFODNN7EXAMPLE"
        # secret_access_key must be forwarded but we don't assert its value in the assertion
        # to avoid echoing it in a test failure message
        assert call_kwargs.get("secret_access_key") is not None
        assert call_kwargs.get("session_token") == "FwoGZXIvYXdzEJr//////////EXAMPLE"

    def test_demo_scan_does_not_receive_credentials(self):
        """Demo scan request must not pass any credential fields."""
        with patch("main.get_boto3_provider") as mock_get:
            r = client.post("/api/scan", json={"mode": "demo", "region": "eu-north-1"})
        # get_boto3_provider must NOT be called for demo mode
        mock_get.assert_not_called()
        assert r.status_code == 200
        assert r.json()["simulated"] is True

    def test_profile_based_scan_still_works(self):
        """Existing profile-based scan path remains functional."""
        mock_provider = MagicMock()
        mock_provider.get_caller_identity.return_value = {
            "account_id": "316658062107",
            "arn": "arn:aws:sts::316658062107:assumed-role/Role/s",
            "user_id": "AROAEXAMPLE:session",
        }
        mock_provider.list_s3_buckets.return_value = []
        mock_provider.list_security_groups.return_value = []

        with patch("main.get_boto3_provider", return_value=mock_provider) as mock_get:
            r = client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
                "aws_profile": "cloudguard",
                # no explicit creds
            })

        assert r.status_code == 200
        # When no explicit creds, profile should be forwarded
        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs.get("access_key_id") is None
        assert call_kwargs.get("secret_access_key") is None
