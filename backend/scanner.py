"""
Scanner orchestrator — coordinates provider + analyzers to produce ScanResult.

The Scanner accepts any ScannerProvider implementation and calls only the
interface methods. It does not import SimulatedScannerProvider directly,
preserving the Session 2 extension point.
"""
from __future__ import annotations

import traceback
from datetime import datetime, timezone

from analyzers.ec2_rules import analyze_security_group
from analyzers.s3_rules import analyze_s3_bucket
from models import SEVERITY_ORDER, Finding, ScanResult, Severity, Warning
from providers.base import ScannerProvider


class Scanner:
    """Orchestrates scanning using any ScannerProvider implementation."""

    def __init__(self, provider: ScannerProvider) -> None:
        self._provider = provider

    def run(self, region: str = "us-east-1") -> ScanResult:
        """Execute a full scan session and return a ScanResult.

        Catches per-resource errors as Warnings so partial failures don't
        abort the entire scan.
        """
        all_findings: list[Finding] = []
        all_warnings: list[Warning] = []

        # --- S3 scanning ---
        try:
            buckets = self._provider.list_s3_buckets()
        except RuntimeError as exc:
            all_warnings.append(Warning(
                resource_id="s3:all-buckets",
                reason=f"Failed to load S3 bucket configurations: {exc}",
            ))
            buckets = []

        for bucket in buckets:
            try:
                findings = analyze_s3_bucket(bucket)
                all_findings.extend(findings)
            except Exception as exc:
                all_warnings.append(Warning(
                    resource_id=f"s3:{bucket.name}",
                    reason=f"Error analyzing bucket '{bucket.name}': {exc}",
                ))

        # --- EC2 scanning ---
        try:
            security_groups = self._provider.list_security_groups(region)
        except RuntimeError as exc:
            all_warnings.append(Warning(
                resource_id="ec2:all-security-groups",
                reason=f"Failed to load security group configurations: {exc}",
            ))
            security_groups = []

        for sg in security_groups:
            try:
                findings = analyze_security_group(sg)
                all_findings.extend(findings)
            except Exception as exc:
                all_warnings.append(Warning(
                    resource_id=f"ec2:{sg.group_id}",
                    reason=f"Error analyzing security group '{sg.group_id}': {exc}",
                ))

        # --- Build summary ---
        summary = {sev.value: 0 for sev in SEVERITY_ORDER}
        for finding in all_findings:
            summary[finding.severity.value] = summary.get(finding.severity.value, 0) + 1

        return ScanResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            simulated=True,
            region=region,
            findings=all_findings,
            warnings=all_warnings,
            summary=summary,
        )
