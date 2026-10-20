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
# Provider factory
# ---------------------------------------------------------------------------

def get_simulated_provider():
    """Return the SimulatedScannerProvider (demo mode).

    Always available — no AWS credentials required.
    """
    from providers.simulated import SimulatedScannerProvider
    return SimulatedScannerProvider()


def get_boto3_provider(profile: str | None = None, region: str | None = None):
    """Return a Boto3ScannerProvider for the given profile and region.

    Parameters
    ----------
    profile:
        AWS CLI profile name. Defaults to DEFAULT_AWS_PROFILE (env var AWS_PROFILE, or 'default').
        Never hardcoded — always resolved from request or env var.
    region:
        AWS region for EC2 operations. Defaults to DEFAULT_AWS_REGION.

    Raises CredentialError if the profile is missing or credentials are invalid.
    Never called for demo mode.
    """
    from providers.boto3_provider import Boto3ScannerProvider
    resolved_profile = profile or DEFAULT_AWS_PROFILE
    resolved_region = region or DEFAULT_AWS_REGION
    return Boto3ScannerProvider(profile_name=resolved_profile, region=resolved_region)


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
