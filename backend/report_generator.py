"""
Report generation for CloudGuard AI — produces JSON and CSV export files.

Both formats include a 'simulated' field/column derived from the actual
ScanResult.simulated value, so the export accurately reflects whether
findings came from JSON fixtures (Session 1) or real AWS APIs (Session 2).
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

    The 'simulated' field reflects the actual scan source:
      true  = JSON fixture data (demo mode)
      false = real AWS API data (live mode)
    """
    data = result.model_dump(mode="json")
    ordered = {
        "simulated": result.simulated,         # actual value, not hardcoded True
        "scan_id": data["scan_id"],
        "timestamp": data["timestamp"],
        "region": data["region"],
        "aws_account_id": data.get("aws_account_id"),
        "aws_identity_arn": data.get("aws_identity_arn"),
        "summary": data["summary"],
        "findings": data["findings"],
        "warnings": data["warnings"],
    }
    return json.dumps(ordered, indent=2, ensure_ascii=False).encode("utf-8")


def generate_csv_report(result: ScanResult) -> bytes:
    """Serialize a ScanResult findings list to UTF-8 CSV bytes.

    One row per finding. The 'simulated' column reflects the actual scan source.
    Multi-line fields have newlines replaced with spaces.
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()

    simulated_str = "true" if result.simulated else "false"

    for finding in result.findings:
        evidence_str = json.dumps(finding.evidence, separators=(",", ":"))
        writer.writerow({
            "simulated": simulated_str,
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


def export_filename(scan_id: str, extension: str) -> str:
    """Generate a deterministic filename for a specific scan export."""
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # Include a short scan_id prefix so files from different scans are distinguishable
    short_id = scan_id[:8]
    return f"cloudguard-findings-{date_str}-{short_id}.{extension}"
