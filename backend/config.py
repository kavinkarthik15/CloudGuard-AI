"""
Application configuration for CloudGuard AI.

SCANNER_PROVIDER controls the default scan mode when no 'mode' is sent in the
request body. Explicit per-request mode always takes precedence.

  - "simulated" (default, Session 1): demo mode, JSON fixtures, no AWS calls.
  - "boto3" (Session 2): enables live mode; still requires mode="live" per request.

AWS_PROFILE: default AWS CLI profile for live scans. Can be overridden per request.
  Defaults to "default" (the standard AWS SDK default profile name).
  Set the AWS_PROFILE environment variable to use a different profile by default.
  Never hardcode credentials here.

AWS_REGION: default region for EC2 security group discovery.
  Can be overridden per request.
"""
from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Core settings (read from environment variables with defaults)
# ---------------------------------------------------------------------------

SCANNER_PROVIDER: str = os.environ.get("SCANNER_PROVIDER", "simulated").lower()

# Default AWS profile for live scans.
# Reads from AWS_PROFILE env var first (standard AWS SDK convention).
# Falls back to "default" — the standard boto3/botocore default profile name.
# Never hardcoded to a specific named profile.
DEFAULT_AWS_PROFILE: str = os.environ.get("AWS_PROFILE", "default")

# Default region for EC2 scanning (can be overridden per request)
DEFAULT_AWS_REGION: str = os.environ.get("AWS_DEFAULT_REGION", "eu-north-1")

CORS_ORIGINS: list[str] = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:5173,http://localhost:4173,http://127.0.0.1:5173,http://127.0.0.1:4173"
    ).split(",")
    if origin.strip()
]

# ---------------------------------------------------------------------------
# Demo-only deployment mode
# ---------------------------------------------------------------------------

# Set ALLOW_LIVE_AWS_SCANS=false to restrict the application to Demo Mode only.
# This is intended for public or shared deployments where live AWS credential
# entry should not be permitted.
#
# When false, all endpoints that create a Boto3 session or accept AWS
# credentials are rejected with HTTP 403 LIVE_AWS_DISABLED.
#
# Demo-mode scanning and all demo-related APIs continue to work normally.
# Default: true (allows live scanning in local development).
ALLOW_LIVE_AWS_SCANS: bool = os.environ.get(
    "ALLOW_LIVE_AWS_SCANS", "true"
).lower().strip() not in ("false", "0", "no", "off")

# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

def get_simulated_provider():
    """Return the SimulatedScannerProvider (demo mode).

    Always available — no AWS credentials required.
    """
    from providers.simulated import SimulatedScannerProvider
    return SimulatedScannerProvider()


def get_boto3_provider(
    profile: str | None = None,
    region: str | None = None,
    access_key_id: str | None = None,
    secret_access_key: str | None = None,
    session_token: str | None = None,
):
    """Return a Boto3ScannerProvider for the given profile or explicit credentials.

    When access_key_id and secret_access_key are supplied, the provider uses
    them directly and does NOT fall back to the profile or the default
    credential chain.

    When only profile is supplied, the existing profile-based path is used.

    Parameters
    ----------
    profile:
        AWS CLI profile name. Used when explicit credentials are absent.
    region:
        AWS region for EC2 operations.
    access_key_id, secret_access_key, session_token:
        Explicit credentials for the local-testing credential-entry flow.
        Never logged. Never persisted beyond this request.

    Raises CredentialError if credentials are missing or invalid.
    Never called for demo mode.
    """
    from providers.boto3_provider import Boto3ScannerProvider
    resolved_profile = profile or DEFAULT_AWS_PROFILE
    resolved_region = region or DEFAULT_AWS_REGION
    return Boto3ScannerProvider(
        profile_name=resolved_profile,
        region=resolved_region,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
    )


def get_scanner_provider():
    """Return the default provider based on SCANNER_PROVIDER env var.

    Used only for backward compatibility with the startup lifespan provider
    initialization. Individual requests always call get_simulated_provider()
    or get_boto3_provider() directly based on the per-request mode.
    """
    if SCANNER_PROVIDER == "simulated":
        return get_simulated_provider()

    if SCANNER_PROVIDER == "boto3":
        return get_boto3_provider()

    raise ValueError(
        f"Unknown SCANNER_PROVIDER: '{SCANNER_PROVIDER}'. "
        "Valid values: 'simulated', 'boto3'."
    )
