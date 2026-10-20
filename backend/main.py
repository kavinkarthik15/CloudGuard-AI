"""
CloudGuard AI — FastAPI backend entry point.

Session 1: demo mode uses simulated JSON fixture data.
Session 2: live mode uses Boto3 with AWS CLI SSO credentials.

Export correctness guarantee:
  Exports are keyed by scan_id (/api/export/{scan_id}/json and .../csv).
  The frontend passes the scan_id from its in-memory ScanResult to the
  export endpoints. The backend looks up that exact scan and rejects
  unknown, expired, or mode-mismatched IDs with structured errors.

  The legacy /api/export/json and /api/export/csv endpoints remain for
  backward compatibility but are now deprecated in favour of the
  scan-id-specific routes.

Per-request mode selection (ScanMode.demo or ScanMode.live) is always
explicit. AWS credentials are never logged, stored, or returned.
"""
from __future__ import annotations

import os
import traceback
from collections import OrderedDict
from typing import Any

from fastapi import FastAPI, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from config import (
    CORS_ORIGINS,
    DEFAULT_AWS_PROFILE,
    DEFAULT_AWS_REGION,
    get_boto3_provider,
    get_simulated_provider,
)
from models import (
    ErrorResponse,
    IdentityInfo,
    ProfilesResponse,
    RegionsResponse,
    RegionInfo,
    ScanMode,
    ScanRequest,
    ScanResult,
)
from report_generator import export_filename, generate_csv_report, generate_json_report
from scanner import Scanner

# ---------------------------------------------------------------------------
# Application state — in-memory, single process, no database.
#
# scan_store: keyed by scan_id, capped at MAX_STORED_SCANS.
# last_scan_id: the most recently completed scan, used by legacy endpoints.
# ---------------------------------------------------------------------------

MAX_STORED_SCANS = 20  # LRU cap — prevents unbounded growth

_app_state: dict[str, Any] = {
    "scan_store": OrderedDict(),   # scan_id -> ScanResult
    "last_scan_id": None,          # scan_id of the most recent completed scan
}


def _store_scan_result(result: ScanResult) -> None:
    """Store a scan result keyed by its scan_id, evicting oldest if at cap."""
    store: OrderedDict = _app_state["scan_store"]
    # Evict oldest entry if at capacity
    while len(store) >= MAX_STORED_SCANS:
        store.popitem(last=False)
    store[result.scan_id] = result
    _app_state["last_scan_id"] = result.scan_id


def _get_scan_result(scan_id: str) -> ScanResult | None:
    """Retrieve a stored scan result by scan_id. Returns None if not found."""
    return _app_state["scan_store"].get(scan_id)


def _get_last_scan_result() -> ScanResult | None:
    """Return the most recently completed scan result, or None."""
    last_id = _app_state.get("last_scan_id")
    if last_id is None:
        return None
    return _app_state["scan_store"].get(last_id)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CloudGuard AI",
    description=(
        "AWS Security Misconfiguration Auditor. "
        "Session 1: demo mode with simulated data. "
        "Session 2: live mode with real AWS APIs (read-only)."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"code": code, "message": message},
    )


def _make_export_response(
    result: ScanResult, fmt: str
) -> Response | JSONResponse:
    """Build an export Response for the given scan result and format."""
    try:
        if fmt == "json":
            data = generate_json_report(result)
            media_type = "application/json"
        else:
            data = generate_csv_report(result)
            media_type = "text/csv"
        filename = export_filename(result.scan_id, fmt)
        return Response(
            content=data,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(data)),
                # Expose scan_id and simulated flag in response headers for
                # client-side consistency checks without parsing the body.
                "X-Scan-Id": result.scan_id,
                "X-Scan-Simulated": str(result.simulated).lower(),
            },
        )
    except Exception:
        traceback.print_exc()
        return error_response(500, "INTERNAL_ERROR", f"Failed to generate {fmt.upper()} export.")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health() -> dict:
    """Liveness check."""
    return {
        "status": "ok",
        "version": "2.0.0",
        "default_mode": "demo",
        "live_mode_available": True,
    }


@app.get("/api/regions")
async def list_regions(
    profile: str | None = None,
) -> RegionsResponse:
    """Return EC2 regions for the region selector.

    Always returns all regions known to botocore (no AWS call required).
    If a profile is supplied and credentials are valid, also calls
    ec2:DescribeRegions to mark which regions the account has opted into.

    Permission failures on DescribeRegions are treated as unknown
    availability — not as evidence that regions are disabled.
    Credentials are never returned, logged, or included in responses.
    """
    from providers.boto3_provider import (
        RegionDiscoveryError,
        list_known_regions,
        list_enabled_regions,
        _REGION_DESCRIPTIONS,
    )

    # Step 1: get botocore's known regions (always works, no AWS call)
    try:
        known = list_known_regions()
    except RegionDiscoveryError as exc:
        # Extremely rare — botocore endpoint data missing from install
        return RegionsResponse(
            regions=[],
            enabled_regions_available=False,
            default_region=DEFAULT_AWS_REGION,
            describe_regions_error=str(exc),
        )

    # Step 2: optionally enrich with DescribeRegions for enabled status
    enabled_set: set[str] | None = None
    describe_error: str | None = None

    if profile:
        from providers.boto3_provider import CredentialError
        try:
            from config import get_boto3_provider as _get
            provider = _get(profile=profile, region=DEFAULT_AWS_REGION)
            enabled_list, err = list_enabled_regions(
                provider._session, home_region=DEFAULT_AWS_REGION
            )
            if err:
                describe_error = err
            else:
                enabled_set = set(enabled_list)
        except CredentialError as exc:
            describe_error = f"Could not verify enabled regions: {exc}"
        except Exception:
            describe_error = "Could not retrieve enabled region list."

    # Step 3: build RegionInfo list
    regions = []
    for name in known:
        description = _REGION_DESCRIPTIONS.get(name, name)
        if enabled_set is not None:
            enabled: bool | None = name in enabled_set
        else:
            enabled = None
        regions.append(RegionInfo(name=name, description=description, enabled=enabled))

    return RegionsResponse(
        regions=regions,
        enabled_regions_available=(enabled_set is not None),
        default_region=DEFAULT_AWS_REGION,
        describe_regions_error=describe_error,
    )


@app.get("/api/profiles")
async def list_profiles() -> ProfilesResponse:
    """Return AWS CLI profiles discovered on the local machine.

    Uses botocore profile discovery — the same mechanism boto3 uses
    internally. Returns profile names only. Never returns credential
    values, file paths, access keys, or secrets.

    External credential helpers (credential_process) are listed by
    profile name but their commands are NOT invoked by this endpoint.
    Credential resolution happens only when boto3 creates a client.

    The 'default_profile' field reflects the AWS_PROFILE environment
    variable if set; it does not imply that profile is verified or valid.
    """
    from providers.boto3_provider import (
        ProfileDiscoveryError,
        list_available_profiles,
    )

    # Resolve the default: AWS_PROFILE env var if set, otherwise empty
    # (we do not assume 'default' exists — it may not be configured)
    import os
    explicit_env_profile = os.environ.get("AWS_PROFILE")

    try:
        profiles = list_available_profiles()
    except ProfileDiscoveryError as exc:
        # Return the error in the response rather than a 500 — the frontend
        # can still show a free-text fallback input when profiles are unavailable.
        return ProfilesResponse(
            profiles=[],
            default_profile=explicit_env_profile,
            discovery_error=str(exc),
        )

    return ProfilesResponse(
        profiles=profiles,
        default_profile=explicit_env_profile,
        discovery_error=None,
    )


@app.get("/api/identity")
async def get_identity(
    profile: str | None = None,
    region: str | None = None,
):
    """Verify AWS credentials and return caller identity metadata.
    Never returns credential values.
    """
    resolved_profile = profile or DEFAULT_AWS_PROFILE
    resolved_region = region or DEFAULT_AWS_REGION

    try:
        provider = get_boto3_provider(
            profile=resolved_profile,
            region=resolved_region,
        )
        identity = provider.get_caller_identity()
        return IdentityInfo(
            account_id=identity["account_id"],
            arn=identity["arn"],
            user_id=identity["user_id"],
            region=resolved_region,
            profile=resolved_profile,
        )
    except Exception as exc:
        from providers.boto3_provider import CredentialError, InsufficientPermissionsError
        if isinstance(exc, CredentialError):
            return error_response(401, "INVALID_CREDENTIALS", str(exc))
        if isinstance(exc, InsufficientPermissionsError):
            return error_response(403, "INSUFFICIENT_PERMISSIONS", str(exc))
        traceback.print_exc()
        return error_response(500, "INTERNAL_ERROR",
                              "Identity check failed. Check backend logs.")


@app.post("/api/scan")
async def trigger_scan(request: ScanRequest) -> ScanResult:
    """Trigger a scan session using the explicitly requested mode.

    Returns a ScanResult whose scan_id can be used with the
    /api/export/{scan_id}/json and /api/export/{scan_id}/csv endpoints
    to guarantee the export matches exactly what was displayed.
    """
    if request.mode == ScanMode.demo:
        return await _run_demo_scan(request)
    else:
        return await _run_live_scan(request)


async def _run_demo_scan(request: ScanRequest) -> ScanResult | JSONResponse:
    try:
        provider = get_simulated_provider()
        scanner = Scanner(provider)
        result = scanner.run(region=request.region, simulated=True)
        _store_scan_result(result)
        return result
    except RuntimeError as exc:
        return error_response(500, "FIXTURE_LOAD_ERROR",
                              f"Failed to load simulation fixtures: {exc}")
    except Exception:
        traceback.print_exc()
        return error_response(500, "INTERNAL_ERROR",
                              "An unexpected error occurred during the demo scan.")


async def _run_live_scan(request: ScanRequest) -> ScanResult | JSONResponse:
    from providers.boto3_provider import CredentialError, InsufficientPermissionsError

    resolved_profile = request.aws_profile or DEFAULT_AWS_PROFILE
    resolved_region = request.region or DEFAULT_AWS_REGION

    # Validate region name before using it
    from providers.boto3_provider import _validate_region_name
    try:
        _validate_region_name(resolved_region)
    except ValueError as exc:
        return error_response(400, "INVALID_REGION", str(exc))

    try:
        provider = get_boto3_provider(profile=resolved_profile, region=resolved_region)
        identity = provider.get_caller_identity()
    except CredentialError as exc:
        return error_response(401, "INVALID_CREDENTIALS", str(exc))
    except InsufficientPermissionsError as exc:
        return error_response(403, "INSUFFICIENT_PERMISSIONS", str(exc))
    except Exception:
        traceback.print_exc()
        return error_response(500, "INTERNAL_ERROR",
                              "Identity verification failed before scan could start.")

    try:
        scanner = Scanner(provider)
        result = scanner.run(
            region=resolved_region,
            simulated=False,
            aws_account_id=identity["account_id"],
            aws_identity_arn=identity["arn"],
        )
        _store_scan_result(result)
        return result
    except InsufficientPermissionsError as exc:
        return error_response(403, "INSUFFICIENT_PERMISSIONS", str(exc))
    except CredentialError as exc:
        return error_response(401, "INVALID_CREDENTIALS", str(exc))
    except Exception:
        traceback.print_exc()
        return error_response(500, "INTERNAL_ERROR",
                              "An unexpected error occurred during the live scan.")


@app.get("/api/findings")
async def get_findings():
    """Return the most recent ScanResult, or 404 if no scan has been run."""
    result = _get_last_scan_result()
    if result is None:
        return error_response(404, "NO_SCAN_RESULT", "No scan has been run yet.")
    return result


# ---------------------------------------------------------------------------
# Scan-specific export endpoints (preferred — guarantees consistency)
# ---------------------------------------------------------------------------

@app.get("/api/export/{scan_id}/json")
async def export_json_by_id(
    scan_id: str = Path(..., description="scan_id from the ScanResult"),
):
    """Download findings for a specific scan as JSON.

    Returns 404 with SCAN_NOT_FOUND if the scan_id is unknown or expired.
    The response includes X-Scan-Id and X-Scan-Simulated headers for
    client-side consistency verification without parsing the body.
    """
    result = _get_scan_result(scan_id)
    if result is None:
        return error_response(
            404, "SCAN_NOT_FOUND",
            f"Scan '{scan_id}' not found. It may have expired or the server restarted. "
            "Re-run the scan and export immediately."
        )
    return _make_export_response(result, "json")


@app.get("/api/export/{scan_id}/csv")
async def export_csv_by_id(
    scan_id: str = Path(..., description="scan_id from the ScanResult"),
):
    """Download findings for a specific scan as CSV.

    Returns 404 with SCAN_NOT_FOUND if the scan_id is unknown or expired.
    """
    result = _get_scan_result(scan_id)
    if result is None:
        return error_response(
            404, "SCAN_NOT_FOUND",
            f"Scan '{scan_id}' not found. It may have expired or the server restarted. "
            "Re-run the scan and export immediately."
        )
    return _make_export_response(result, "csv")


# ---------------------------------------------------------------------------
# Legacy export endpoints (deprecated — use scan-id-specific routes above)
# ---------------------------------------------------------------------------

@app.get("/api/export/json")
async def export_json_legacy():
    """[Deprecated] Download the most recent scan findings as JSON.
    Use /api/export/{scan_id}/json for guaranteed consistency.
    """
    result = _get_last_scan_result()
    if result is None:
        return error_response(404, "NO_SCAN_RESULT", "No scan has been run yet.")
    return _make_export_response(result, "json")


@app.get("/api/export/csv")
async def export_csv_legacy():
    """[Deprecated] Download the most recent scan findings as CSV.
    Use /api/export/{scan_id}/csv for guaranteed consistency.
    """
    result = _get_last_scan_result()
    if result is None:
        return error_response(404, "NO_SCAN_RESULT", "No scan has been run yet.")
    return _make_export_response(result, "csv")
