"""
Phase 4C regression tests — AWS Session and Identity Reliability.

Tests cover:
  - SESSION_EXPIRED (401) — ExpiredToken, TokenRetrievalError, TokenRefreshRequired
  - NO_CREDENTIALS (401) — ProfileNotFound, NoCredentialsError, MissingCredentialsError
  - INSUFFICIENT_PERMISSIONS (403) — AccessDenied on sts:GetCallerIdentity
  - NETWORK_ERROR (503) — connectivity failures
  - Invalid profile names (path traversal, injection characters)
  - Scan aborts on expired session — identity pre-check prevents scan from running
  - Scan aborts on missing credentials

Classification: MOCKED — all AWS interactions use MagicMock.
No real AWS API calls are made. All profile names and credentials are fake.
"""
from __future__ import annotations

import pytest
import botocore.exceptions
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# TestClient setup — app must be imported AFTER path setup by pytest.ini
# ---------------------------------------------------------------------------

from main import app, _app_state

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_scan_store():
    """Ensure scan_store is empty before and after each test."""
    _app_state["scan_store"].clear()
    _app_state["last_scan_id"] = None
    yield
    _app_state["scan_store"].clear()
    _app_state["last_scan_id"] = None


def _mock_provider_raising(exc_instance):
    """Return a MagicMock provider whose get_caller_identity raises exc_instance."""
    mock_provider = MagicMock()
    mock_provider.get_caller_identity.side_effect = exc_instance
    return mock_provider


# ---------------------------------------------------------------------------
# Helper: make a botocore ClientError
# ---------------------------------------------------------------------------

def _client_error(code: str, message: str = "test") -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


# ---------------------------------------------------------------------------
# /api/identity — SESSION_EXPIRED
# ---------------------------------------------------------------------------

class TestIdentitySessionExpired:
    def test_session_expired_error_returns_401_with_session_expired_code(self):
        """`SessionExpiredError` from provider → HTTP 401 SESSION_EXPIRED."""
        from providers.boto3_provider import SessionExpiredError
        provider = _mock_provider_raising(SessionExpiredError("SSO expired"))

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "test-profile", "region": "eu-north-1"
            })

        assert r.status_code == 401
        data = r.json()
        assert data["code"] == "SESSION_EXPIRED"
        assert "sso login" in data["message"].lower() or "aws sso" in data["message"].lower()
        # Must NOT contain raw token values
        assert "AKIA" not in data["message"]
        assert "secret" not in data["message"].lower()

    def test_token_retrieval_error_in_credential_error_codes_routes_to_session_expired(self):
        """`ClientError(TokenRetrievalError)` → SessionExpiredError → 401 SESSION_EXPIRED.

        TokenRetrievalError is in _CREDENTIAL_ERROR_CODES, so Boto3ScannerProvider.get_caller_identity
        raises SessionExpiredError, which main.py maps to SESSION_EXPIRED.
        """
        from providers.boto3_provider import SessionExpiredError
        # Simulate what boto3_provider raises after seeing TokenRetrievalError from STS
        provider = _mock_provider_raising(
            SessionExpiredError("TokenRetrievalError: SSO cache expired")
        )

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "sso-profile", "region": "eu-north-1"
            })

        assert r.status_code == 401
        assert r.json()["code"] == "SESSION_EXPIRED"

    def test_expired_token_exception_routes_to_session_expired(self):
        """`SessionExpiredError` wrapping an ExpiredTokenException → 401 SESSION_EXPIRED."""
        from providers.boto3_provider import SessionExpiredError
        provider = _mock_provider_raising(
            SessionExpiredError("ExpiredTokenException from STS")
        )

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "expired-profile", "region": "us-east-1"
            })

        assert r.status_code == 401
        assert r.json()["code"] == "SESSION_EXPIRED"


# ---------------------------------------------------------------------------
# /api/identity — NO_CREDENTIALS
# ---------------------------------------------------------------------------

class TestIdentityNoCredentials:
    def test_missing_credentials_error_returns_401_no_credentials(self):
        """`MissingCredentialsError` from provider → HTTP 401 NO_CREDENTIALS."""
        from providers.boto3_provider import MissingCredentialsError
        provider = _mock_provider_raising(
            MissingCredentialsError("No credentials for profile 'ghost'")
        )

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "ghost", "region": "eu-north-1"
            })

        assert r.status_code == 401
        data = r.json()
        assert data["code"] == "NO_CREDENTIALS"
        assert "configure" in data["message"].lower() or "credentials" in data["message"].lower()

    def test_profile_not_found_during_provider_construction_returns_401(self):
        """`ProfileNotFound` raised during Boto3ScannerProvider.__init__ → 401 NO_CREDENTIALS.

        config.get_boto3_provider() calls Boto3ScannerProvider(profile_name=...).
        _create_session() raises MissingCredentialsError on ProfileNotFound.
        The endpoint catches MissingCredentialsError and returns NO_CREDENTIALS.
        """
        from providers.boto3_provider import MissingCredentialsError

        with patch("main.get_boto3_provider",
                   side_effect=MissingCredentialsError("Profile 'ghost' not found")):
            r = client.get("/api/identity", params={
                "profile": "ghost", "region": "eu-north-1"
            })

        assert r.status_code == 401
        data = r.json()
        assert data["code"] == "NO_CREDENTIALS"


# ---------------------------------------------------------------------------
# /api/identity — INSUFFICIENT_PERMISSIONS
# ---------------------------------------------------------------------------

class TestIdentityStsAccessDenied:
    def test_access_denied_returns_403_insufficient_permissions(self):
        """`InsufficientPermissionsError` from provider → HTTP 403 INSUFFICIENT_PERMISSIONS."""
        from providers.boto3_provider import InsufficientPermissionsError
        provider = _mock_provider_raising(
            InsufficientPermissionsError("sts:GetCallerIdentity denied")
        )

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "restricted-profile", "region": "eu-north-1"
            })

        assert r.status_code == 403
        data = r.json()
        assert data["code"] == "INSUFFICIENT_PERMISSIONS"
        assert "iam" in data["message"].lower() or "permission" in data["message"].lower() or \
               "GetCallerIdentity" in data["message"] or "denied" in data["message"].lower()


# ---------------------------------------------------------------------------
# /api/identity — NETWORK_ERROR
# ---------------------------------------------------------------------------

class TestIdentityNetworkError:
    def test_network_error_returns_503(self):
        """`NetworkError` from provider → HTTP 503 NETWORK_ERROR."""
        from providers.boto3_provider import NetworkError
        provider = _mock_provider_raising(
            NetworkError("Could not reach AWS endpoint")
        )

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "test-profile", "region": "eu-north-1"
            })

        assert r.status_code == 503
        data = r.json()
        assert data["code"] == "NETWORK_ERROR"
        assert "internet" in data["message"].lower() or "connectivity" in data["message"].lower() or \
               "connect" in data["message"].lower()


# ---------------------------------------------------------------------------
# /api/identity — Invalid profile names (injection / traversal)
# ---------------------------------------------------------------------------

class TestIdentityInvalidProfileNames:
    def test_path_traversal_profile_name_is_rejected(self):
        """Profile name `../evil` must be rejected with 400 INVALID_PROFILE."""
        r = client.get("/api/identity", params={
            "profile": "../evil", "region": "us-east-1"
        })
        assert r.status_code == 400
        assert r.json()["code"] == "INVALID_PROFILE"

    def test_shell_injection_profile_name_is_rejected(self):
        """Profile name with semicolon must be rejected with 400 INVALID_PROFILE."""
        r = client.get("/api/identity", params={
            "profile": "; rm -rf /", "region": "us-east-1"
        })
        assert r.status_code == 400
        assert r.json()["code"] == "INVALID_PROFILE"

    def test_null_byte_profile_name_is_rejected(self):
        """Profile name with null byte must be rejected with 400 INVALID_PROFILE."""
        r = client.get("/api/identity", params={
            "profile": "evil\x00inject", "region": "us-east-1"
        })
        assert r.status_code == 400
        assert r.json()["code"] == "INVALID_PROFILE"


# ---------------------------------------------------------------------------
# /api/scan (live) — aborts on expired session (pre-check)
# ---------------------------------------------------------------------------

class TestScanAbortsOnAuthFailure:
    def test_scan_aborts_on_expired_session_no_result_stored(self):
        """Expired session in identity pre-check → 401 SESSION_EXPIRED, scan NOT run.

        After a failed live scan due to expired session:
          - The endpoint must return 401 with SESSION_EXPIRED
          - No scan result must be stored (GET /api/findings → 404)
        """
        from providers.boto3_provider import SessionExpiredError
        provider = _mock_provider_raising(
            SessionExpiredError("SSO session expired mid-check")
        )

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
                "aws_profile": "sso-profile",
            })

        assert r.status_code == 401
        data = r.json()
        assert data["code"] == "SESSION_EXPIRED"

        # Verify no scan result was stored
        findings_r = client.get("/api/findings")
        assert findings_r.status_code == 404, (
            "A failed live scan must NOT store a result accessible via /api/findings"
        )

    def test_scan_aborts_on_no_credentials_no_result_stored(self):
        """`MissingCredentialsError` in pre-check → 401 NO_CREDENTIALS, no scan stored."""
        from providers.boto3_provider import MissingCredentialsError
        provider = _mock_provider_raising(
            MissingCredentialsError("No credentials for profile 'none'")
        )

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
                "aws_profile": "none",
            })

        assert r.status_code == 401
        assert r.json()["code"] == "NO_CREDENTIALS"

        findings_r = client.get("/api/findings")
        assert findings_r.status_code == 404

    def test_scan_aborts_on_network_error_no_result_stored(self):
        """`NetworkError` in pre-check → 503 NETWORK_ERROR, no scan stored."""
        from providers.boto3_provider import NetworkError
        provider = _mock_provider_raising(
            NetworkError("Cannot reach AWS")
        )

        with patch("main.get_boto3_provider", return_value=provider):
            r = client.post("/api/scan", json={
                "mode": "live",
                "region": "eu-north-1",
                "aws_profile": "test",
            })

        assert r.status_code == 503
        assert r.json()["code"] == "NETWORK_ERROR"

        findings_r = client.get("/api/findings")
        assert findings_r.status_code == 404

    def test_scan_with_invalid_region_returns_400(self):
        """Invalid region name → 400 INVALID_REGION before identity is checked."""
        r = client.post("/api/scan", json={
            "mode": "live",
            "region": "not-a-region",
            "aws_profile": "test",
        })
        assert r.status_code == 400
        assert r.json()["code"] == "INVALID_REGION"


# ---------------------------------------------------------------------------
# Exception subtype inheritance sanity check
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_session_expired_is_subclass_of_credential_error(self):
        from providers.boto3_provider import CredentialError, SessionExpiredError
        assert issubclass(SessionExpiredError, CredentialError)

    def test_missing_credentials_is_subclass_of_credential_error(self):
        from providers.boto3_provider import CredentialError, MissingCredentialsError
        assert issubclass(MissingCredentialsError, CredentialError)

    def test_invalid_profile_is_subclass_of_credential_error(self):
        from providers.boto3_provider import CredentialError, InvalidProfileError
        assert issubclass(InvalidProfileError, CredentialError)

    def test_network_error_is_not_credential_error(self):
        from providers.boto3_provider import CredentialError, NetworkError
        assert not issubclass(NetworkError, CredentialError)

    def test_all_new_classes_importable(self):
        """Smoke test: all Phase 4C exception classes can be imported."""
        from providers.boto3_provider import (  # noqa: F401
            SessionExpiredError,
            MissingCredentialsError,
            InvalidProfileError,
            NetworkError,
        )


# ---------------------------------------------------------------------------
# Direct botocore exceptions (non-ClientError BotoCoreError subclasses)
#
# These exceptions are NOT subclasses of ClientError, so they bypass the
# existing `except botocore.exceptions.ClientError` block in get_caller_identity().
# Each requires an explicit catch clause in the provider — verified here by
# raising the raw botocore exception directly from get_caller_identity.
# ---------------------------------------------------------------------------

class TestBotocoreDirectExceptions:
    """Tests for botocore non-ClientError exceptions raised directly by get_caller_identity."""

    def test_partial_credentials_error_returns_401_no_credentials(self):
        """botocore.exceptions.PartialCredentialsError (non-ClientError) -> 401 NO_CREDENTIALS."""
        exc = botocore.exceptions.PartialCredentialsError(
            provider="env", cred_var="aws_secret_access_key"
        )
        provider = _mock_provider_raising(exc)
        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "partial-creds", "region": "eu-north-1"
            })
        assert r.status_code == 401
        assert r.json()["code"] == "NO_CREDENTIALS"

    def test_token_retrieval_error_direct_returns_401_session_expired(self):
        """botocore.exceptions.TokenRetrievalError (non-ClientError) -> 401 SESSION_EXPIRED."""
        exc = botocore.exceptions.TokenRetrievalError(
            provider="sso", error_msg="SSO token cache expired"
        )
        provider = _mock_provider_raising(exc)
        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "sso-direct", "region": "eu-north-1"
            })
        assert r.status_code == 401
        assert r.json()["code"] == "SESSION_EXPIRED"

    def test_unauthorized_sso_token_error_returns_401_session_expired(self):
        """botocore.exceptions.UnauthorizedSSOTokenError (non-ClientError) -> 401 SESSION_EXPIRED."""
        exc = botocore.exceptions.UnauthorizedSSOTokenError()
        provider = _mock_provider_raising(exc)
        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "sso-profile", "region": "eu-north-1"
            })
        assert r.status_code == 401
        assert r.json()["code"] == "SESSION_EXPIRED"

    def test_sso_token_load_error_returns_401_session_expired(self):
        """botocore.exceptions.SSOTokenLoadError (non-ClientError) -> 401 SESSION_EXPIRED."""
        exc = botocore.exceptions.SSOTokenLoadError(error_msg="token file not found")
        provider = _mock_provider_raising(exc)
        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "sso-profile", "region": "eu-north-1"
            })
        assert r.status_code == 401
        assert r.json()["code"] == "SESSION_EXPIRED"

    def test_credential_retrieval_error_returns_401_session_expired(self):
        """botocore.exceptions.CredentialRetrievalError (non-ClientError) -> 401 SESSION_EXPIRED."""
        exc = botocore.exceptions.CredentialRetrievalError(
            provider="iam-role", error_msg="IMDS unreachable"
        )
        provider = _mock_provider_raising(exc)
        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "ec2-role", "region": "eu-north-1"
            })
        assert r.status_code == 401
        assert r.json()["code"] == "SESSION_EXPIRED"

    def test_refresh_with_mfa_unsupported_returns_401_session_expired(self):
        """botocore.exceptions.RefreshWithMFAUnsupportedError (non-ClientError) -> 401 SESSION_EXPIRED."""
        exc = botocore.exceptions.RefreshWithMFAUnsupportedError()
        provider = _mock_provider_raising(exc)
        with patch("main.get_boto3_provider", return_value=provider):
            r = client.get("/api/identity", params={
                "profile": "mfa-profile", "region": "eu-north-1"
            })
        assert r.status_code == 401
        assert r.json()["code"] == "SESSION_EXPIRED"
