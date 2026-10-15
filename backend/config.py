"""
Application configuration for CloudGuard AI backend.

SCANNER_PROVIDER controls which ScannerProvider implementation is used:
  - "simulated" (default, Session 1): SimulatedScannerProvider loads JSON fixtures.
  - "boto3" (Session 2): Boto3ScannerProvider calls real AWS APIs.
    To enable: set SCANNER_PROVIDER=boto3 and ensure AWS credentials are
    configured via the standard Boto3 credential provider chain.

No real AWS credentials are accepted or stored by this application in Session 1.
"""
from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Core settings (read from environment variables with defaults)
# ---------------------------------------------------------------------------

SCANNER_PROVIDER: str = os.environ.get("SCANNER_PROVIDER", "simulated").lower()

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

def get_scanner_provider():
    """Return the configured ScannerProvider instance.

    Session 1: returns SimulatedScannerProvider.
    Session 2: "boto3" will instantiate Boto3ScannerProvider.
    """
    if SCANNER_PROVIDER == "simulated":
        from providers.simulated import SimulatedScannerProvider
        return SimulatedScannerProvider()

    # Session 2 extension point:
    # if SCANNER_PROVIDER == "boto3":
    #     from providers.boto3_provider import Boto3ScannerProvider
    #     return Boto3ScannerProvider()

    raise ValueError(
        f"Unknown SCANNER_PROVIDER: '{SCANNER_PROVIDER}'. "
        "Valid values: 'simulated'. "
        "(Session 2 will add: 'boto3')"
    )
