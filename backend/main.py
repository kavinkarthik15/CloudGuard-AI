"""
CloudGuard AI — FastAPI backend entry point.

Session 1: All scanning uses simulated JSON fixture data.
No real AWS credentials, Boto3, STS, IAM, or Bedrock are used.
"""
from __future__ import annotations

import traceback
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from config import CORS_ORIGINS, get_scanner_provider
from models import ErrorResponse, ScanRequest, ScanResult
from report_generator import export_filename, generate_csv_report, generate_json_report
from scanner import Scanner

# ---------------------------------------------------------------------------
# Application state — in-memory, single process, no database
# ---------------------------------------------------------------------------

_app_state: dict[str, Any] = {
    "provider": None,
    "last_scan_result": None,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize provider on startup; validate SCANNER_PROVIDER is configured."""
    try:
        _app_state["provider"] = get_scanner_provider()
    except ValueError as exc:
        # Startup will succeed but first scan will fail with a clear message
        _app_state["provider"] = None
        _app_state["startup_error"] = str(exc)
    yield
    # Shutdown: nothing to clean up (no DB, no connections)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CloudGuard AI",
    description=(
        "AWS Security Misconfiguration Auditor — Session 1 (Simulated Data). "
        "No real AWS credentials or API calls are used."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------------------------
# Helper: error response
# ---------------------------------------------------------------------------

def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"code": code, "message": message},
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health() -> dict:
    """Liveness check. Always returns simulated: true in Session 1."""
    return {"status": "ok", "simulated": True, "version": "1.0.0"}


@app.post("/api/scan")
async def trigger_scan(request: ScanRequest) -> ScanResult:
    """Trigger a full scan session using the configured ScannerProvider.

    Session 1: Uses SimulatedScannerProvider with JSON fixture data.
    Returns a ScanResult with simulated=true and all findings.
    """
    provider = _app_state.get("provider")
    if provider is None:
        startup_error = _app_state.get("startup_error", "Provider not initialized.")
        return error_response(500, "INTERNAL_ERROR", startup_error)

    try:
        scanner = Scanner(provider)
        result = scanner.run(region=request.region)
        _app_state["last_scan_result"] = result
        return result
    except RuntimeError as exc:
        # Fixture load errors — structured error
        return error_response(
            500,
            "FIXTURE_LOAD_ERROR",
            f"Failed to load simulation fixtures: {exc}",
        )
    except Exception:
        # Unhandled exceptions — log full traceback, return safe message
        traceback.print_exc()
        return error_response(
            500,
            "INTERNAL_ERROR",
            "An unexpected error occurred during the scan. Please try again.",
        )


@app.get("/api/findings")
async def get_findings():
    """Return the most recent ScanResult, or 404 if no scan has been run."""
    result = _app_state.get("last_scan_result")
    if result is None:
        return error_response(404, "NO_SCAN_RESULT", "No scan has been run yet.")
    return result


@app.get("/api/export/json")
async def export_json():
    """Download the most recent scan findings as a JSON file."""
    result: ScanResult | None = _app_state.get("last_scan_result")
    if result is None:
        return error_response(404, "NO_SCAN_RESULT", "No scan has been run yet.")

    try:
        data = generate_json_report(result)
        filename = export_filename("json")
        return Response(
            content=data,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(data)),
            },
        )
    except Exception:
        traceback.print_exc()
        return error_response(500, "INTERNAL_ERROR", "Failed to generate JSON export.")


@app.get("/api/export/csv")
async def export_csv():
    """Download the most recent scan findings as a CSV file."""
    result: ScanResult | None = _app_state.get("last_scan_result")
    if result is None:
        return error_response(404, "NO_SCAN_RESULT", "No scan has been run yet.")

    try:
        data = generate_csv_report(result)
        filename = export_filename("csv")
        return Response(
            content=data,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(data)),
            },
        )
    except Exception:
        traceback.print_exc()
        return error_response(500, "INTERNAL_ERROR", "Failed to generate CSV export.")
