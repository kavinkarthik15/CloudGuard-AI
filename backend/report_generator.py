"""
Report generation for CloudGuard AI — produces JSON and CSV export files.

Both formats include a 'simulated: true' field/column to clearly identify
that findings originate from simulated configurations, not real AWS scans.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from models import ScanResult

_CSV_FIELDS = [
    "simulated",
    "resource_type",
    "resource_name",
    "severity",
    "title",
    "evidence",
    "risk_explanation",
    "remediation",
]


def generate_json_report(result: ScanResult) -> bytes:
    """Serialize a ScanResult to pretty-printed JSON bytes.

    Always includes "simulated": true at the top level and in each finding
    to prevent confusion with real AWS scan results.
    """
    data = result.model_dump(mode="json")
    # Ensure simulated flag is prominent at the top level
    ordered = {
        "simulated": True,
        "scan_id": data["scan_id"],
        "timestamp": data["timestamp"],
        "region": data["region"],
        "summary": data["summary"],
        "findings": data["findings"],
        "warnings": data["warnings"],
    }
    return json.dumps(ordered, indent=2, ensure_ascii=False).encode("utf-8")


def generate_csv_report(result: ScanResult) -> bytes:
    """Serialize a ScanResult findings list to UTF-8 CSV bytes.

    One row per finding. Multi-line fields have newlines replaced with spaces.
    The 'simulated' column is always 'true'.
    The 'evidence' column is a compact JSON string.
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()

    for finding in result.findings:
        evidence_str = json.dumps(finding.evidence, separators=(",", ":"))
        writer.writerow({
            "simulated": "true",
            "resource_type": finding.resource_type,
            "resource_name": finding.resource_name,
            "severity": finding.severity.value,
            "title": _flatten(finding.title),
            "evidence": _flatten(evidence_str),
            "risk_explanation": _flatten(finding.risk_explanation),
            "remediation": _flatten(finding.remediation),
        })

    return output.getvalue().encode("utf-8")


def _flatten(text: str) -> str:
    """Replace internal newlines with spaces for single-row CSV structure."""
    return text.replace("\n", " ").replace("\r", " ")


def export_filename(extension: str) -> str:
    """Generate a timestamped filename for the export file."""
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"cloudguard-findings-{date_str}.{extension}"
