"""
Scanner orchestrator — coordinates provider + analyzers to produce ScanResult.

The Scanner accepts any ScannerProvider implementation and calls only the
interface methods. It does not import SimulatedScannerProvider or
Boto3ScannerProvider directly, preserving the extension point.

For live (non-simulated) scans, finding text that references simulated data
is rewritten to accurately reflect the live source. The security rules
themselves are unchanged.
"""
from __future__ import annotations

from datetime import datetime, timezone

from analyzers.ec2_rules import analyze_security_group
from analyzers.s3_rules import analyze_s3_bucket
from models import SEVERITY_ORDER, Finding, ScanResult, Severity, Warning
from providers.base import ScannerProvider

# Text substituted in risk_explanation when findings come from live AWS data.
# The S1 analyzers embed this prefix; for live scans it must be replaced.
_SIM_PREFIX = "This finding is based on simulated configuration data."
_LIVE_PREFIX = "This finding is based on live AWS configuration data."


def _rewrite_finding_for_live(finding: Finding) -> Finding:
    """Return a new Finding with live-scan text and simulated=False.

    Uses model_copy to avoid mutating the original (findings are immutable
    once produced by the analyzers).
    """
    new_explanation = finding.risk_explanation.replace(_SIM_PREFIX, _LIVE_PREFIX)
    return finding.model_copy(update={
        "simulated": False,
        "risk_explanation": new_explanation,
    })


class Scanner:
    """Orchestrates scanning using any ScannerProvider implementation."""

    def __init__(self, provider: ScannerProvider) -> None:
        self._provider = provider

    def run(
        self,
        region: str = "us-east-1",
        simulated: bool = True,
        aws_account_id: str | None = None,
        aws_identity_arn: str | None = None,
    ) -> ScanResult:
        """Execute a full scan session and return a ScanResult.

        Parameters
        ----------
        region:
            AWS region for EC2 security group enumeration.
        simulated:
            True for demo mode, False for live AWS mode.
            Controls finding labels and ScanResult.simulated flag.
        aws_account_id:
            Populated for live scans from sts:GetCallerIdentity.
            Never set for simulated scans.
        aws_identity_arn:
            Populated for live scans from sts:GetCallerIdentity.
            Never set for simulated scans.

        The method catches per-resource errors as Warnings so partial
        failures don't abort the entire scan.
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
                if not simulated:
                    findings = [_rewrite_finding_for_live(f) for f in findings]
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
                if not simulated:
                    findings = [_rewrite_finding_for_live(f) for f in findings]
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
            simulated=simulated,
            region=region,
            findings=all_findings,
            warnings=all_warnings,
            summary=summary,
            aws_account_id=aws_account_id,
            aws_identity_arn=aws_identity_arn,
        )
