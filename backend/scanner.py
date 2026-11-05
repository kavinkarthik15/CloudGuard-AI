"""
Scanner orchestrator — coordinates provider + analyzers to produce ScanResult.

The Scanner accepts any ScannerProvider implementation and calls only the
interface methods. It does not import SimulatedScannerProvider or
Boto3ScannerProvider directly, preserving the extension point.

For live (non-simulated) scans, finding text that references simulated data
is rewritten to accurately reflect the live source. The security rules
themselves are unchanged.

Phase 4D: S3BucketConfig carries a typed `scan_warnings` field (list[Warning],
  default empty). Boto3ScannerProvider populates this with per-bucket warnings
  from region-discovery and attribute-fetch failures (e.g. AccessDenied on
  GetBucketLocation). Scanner drains these into the overall warning list so
  they reach ScanResult.warnings and the API response.

Phase 4E: Scanner accepts a `regions` list for multi-region EC2 scanning.
  When `regions` is supplied and the provider exposes
  `list_security_groups_multi_region`, that method is called and returns a
  3-tuple (sgs, scanned_regions, warnings). Falls back to the single-region
  `list_security_groups` path otherwise (backward compatible).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from analyzers.ec2_rules import analyze_security_group
from analyzers.s3_rules import analyze_s3_bucket
from models import SEVERITY_ORDER, Finding, ScanCoverage, ScanResult, Warning
from providers.base import ScannerProvider

logger = logging.getLogger(__name__)

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


def _drain_bucket_warnings(bucket_config: Any) -> list[Warning]:
    """Extract per-bucket warnings attached by Boto3ScannerProvider (Phase 4D).

    Reads the typed `scan_warnings` field on S3BucketConfig (always present,
    defaults to empty list). Works for both simulated and live providers.
    """
    return list(getattr(bucket_config, "scan_warnings", []))


class Scanner:
    """Orchestrates scanning using any ScannerProvider implementation."""

    def __init__(self, provider: ScannerProvider) -> None:
        self._provider = provider

    def run(
        self,
        region: str = "us-east-1",
        regions: list[str] | None = None,
        simulated: bool = True,
        aws_account_id: str | None = None,
        aws_identity_arn: str | None = None,
    ) -> ScanResult:
        """Execute a full scan session and return a ScanResult.

        Parameters
        ----------
        region:
            Primary AWS region (backward-compat single-region path).
        regions:
            Phase 4E: list of regions to scan for EC2 security groups.
            Overrides 'region' when supplied. May include "ALL_ENABLED" sentinel.
        simulated:
            True for demo mode, False for live AWS mode.
        aws_account_id, aws_identity_arn:
            Identity metadata for live scans only.
        """
        all_findings: list[Finding] = []
        all_warnings: list[Warning] = []

        # ── S3 scanning (Phase 4D: global, not region-filtered) ───────────
        s3_buckets_requested = 0
        s3_buckets_scanned = 0
        s3_buckets_failed = 0

        try:
            buckets = self._provider.list_s3_buckets()
            s3_buckets_requested = len(buckets)
            logger.info("S3: discovered %d bucket(s)", s3_buckets_requested)
        except RuntimeError as exc:
            all_warnings.append(Warning(
                resource_id="s3:all-buckets",
                reason=f"Failed to load S3 bucket configurations: {exc}",
            ))
            buckets = []

        for bucket in buckets:
            # Phase 4D: drain per-bucket warnings from regional client work
            bucket_warnings = _drain_bucket_warnings(bucket)
            all_warnings.extend(bucket_warnings)

            try:
                findings = analyze_s3_bucket(bucket)
                if not simulated:
                    findings = [_rewrite_finding_for_live(f) for f in findings]
                # Phase 4D: inject bucket region into evidence
                enriched = []
                for f in findings:
                    enriched_evidence = dict(f.evidence)
                    enriched_evidence.setdefault("bucket_region", bucket.region)
                    enriched.append(f.model_copy(update={"evidence": enriched_evidence}))
                all_findings.extend(enriched)
                s3_buckets_scanned += 1
            except Exception as exc:
                s3_buckets_failed += 1
                all_warnings.append(Warning(
                    resource_id=f"s3:{bucket.name}",
                    reason=f"Error analyzing bucket '{bucket.name}': {exc}",
                ))

        # ── EC2 scanning (Phase 4E: single or multi-region) ───────────────
        requested_regions: list[str] = []
        scanned_regions: list[str] = []
        failed_regions: list[str] = []
        ec2_sgs_discovered = 0
        ec2_sgs_evaluated = 0
        ec2_sgs_failed = 0

        # Determine effective region list
        effective_regions = regions if regions else [region]
        requested_regions = list(effective_regions)

        # Check if provider supports multi-region scanning (Boto3ScannerProvider)
        _multi_fn = getattr(self._provider, "list_security_groups_multi_region", None)

        if len(effective_regions) == 1 and effective_regions[0] != "ALL_ENABLED":
            # Single-region path (backward compat)
            scan_region = effective_regions[0]
            try:
                security_groups = self._provider.list_security_groups(scan_region)
                scanned_regions = [scan_region]
                ec2_sgs_discovered = len(security_groups)
                logger.info("EC2: discovered %d security group(s) in %s",
                            ec2_sgs_discovered, scan_region)
            except RuntimeError as exc:
                all_warnings.append(Warning(
                    resource_id="ec2:all-security-groups",
                    reason=f"Failed to load security group configurations: {exc}",
                ))
                security_groups = []
                failed_regions = [scan_region]

            for sg in security_groups:
                try:
                    findings = analyze_security_group(sg)
                    if not simulated:
                        findings = [_rewrite_finding_for_live(f) for f in findings]
                    # Phase 4E: inject region into evidence
                    enriched = []
                    for f in findings:
                        enriched_evidence = dict(f.evidence)
                        enriched_evidence.setdefault("region", sg.region)
                        enriched.append(f.model_copy(update={"evidence": enriched_evidence}))
                    all_findings.extend(enriched)
                    ec2_sgs_evaluated += 1
                except Exception as exc:
                    ec2_sgs_failed += 1
                    all_warnings.append(Warning(
                        resource_id=f"ec2:{sg.group_id}",
                        reason=f"Error analyzing security group '{sg.group_id}': {exc}",
                    ))

        elif _multi_fn is not None:
            # Multi-region path (Boto3ScannerProvider)
            try:
                security_groups, provider_scanned, regional_warnings = _multi_fn(effective_regions)
                all_warnings.extend(regional_warnings)
                ec2_sgs_discovered = len(security_groups)
                # scanned_regions comes from the provider's explicit tracking —
                # includes regions that returned zero SGs (empty ≠ failed).
                scanned_regions = list(provider_scanned)
                # failed_regions: extract from warning resource_ids
                # (format: "ec2:{region}:security-groups" → index 1 is the region)
                _failed_from_warnings = [
                    w.resource_id.split(":")[1]
                    for w in regional_warnings
                    if w.resource_id.startswith("ec2:") and len(w.resource_id.split(":")) >= 2
                ]
                failed_regions = _failed_from_warnings
                # If ALL_ENABLED was used, update requested_regions to reflect
                # the actual regions that were attempted (scanned + failed)
                if "ALL_ENABLED" in effective_regions:
                    requested_regions = sorted(
                        set(scanned_regions) | set(failed_regions)
                    )
            except Exception as exc:
                all_warnings.append(Warning(
                    resource_id="ec2:multi-region",
                    reason=f"Multi-region EC2 scan failed: {exc}",
                ))
                security_groups = []
                failed_regions = [r for r in requested_regions if r != "ALL_ENABLED"]
                if "ALL_ENABLED" in effective_regions:
                    requested_regions = failed_regions

            for sg in security_groups:
                try:
                    findings = analyze_security_group(sg)
                    if not simulated:
                        findings = [_rewrite_finding_for_live(f) for f in findings]
                    enriched = []
                    for f in findings:
                        enriched_evidence = dict(f.evidence)
                        enriched_evidence.setdefault("region", sg.region)
                        enriched.append(f.model_copy(update={"evidence": enriched_evidence}))
                    all_findings.extend(enriched)
                    ec2_sgs_evaluated += 1
                except Exception as exc:
                    ec2_sgs_failed += 1
                    all_warnings.append(Warning(
                        resource_id=f"ec2:{sg.group_id}",
                        reason=f"Error analyzing security group '{sg.group_id}': {exc}",
                    ))
        else:
            # Fallback: provider doesn't support multi-region, scan primary region only
            scan_region = region
            try:
                security_groups = self._provider.list_security_groups(scan_region)
                scanned_regions = [scan_region]
                ec2_sgs_discovered = len(security_groups)
            except RuntimeError as exc:
                all_warnings.append(Warning(
                    resource_id="ec2:all-security-groups",
                    reason=f"Failed to load security group configurations: {exc}",
                ))
                security_groups = []
                failed_regions = [scan_region]

            for sg in security_groups:
                try:
                    findings = analyze_security_group(sg)
                    if not simulated:
                        findings = [_rewrite_finding_for_live(f) for f in findings]
                    all_findings.extend(findings)
                    ec2_sgs_evaluated += 1
                except Exception as exc:
                    ec2_sgs_failed += 1
                    all_warnings.append(Warning(
                        resource_id=f"ec2:{sg.group_id}",
                        reason=f"Error analyzing security group '{sg.group_id}': {exc}",
                    ))

        # ── Build summary ──────────────────────────────────────────────────
        summary = {sev.value: 0 for sev in SEVERITY_ORDER}
        for finding in all_findings:
            summary[finding.severity.value] = summary.get(finding.severity.value, 0) + 1

        # ── Coverage metadata ──────────────────────────────────────────────
        coverage = ScanCoverage(
            requested_regions=requested_regions,
            scanned_regions=scanned_regions,
            failed_regions=failed_regions,
            s3_buckets_requested=s3_buckets_requested,
            s3_buckets_scanned=s3_buckets_scanned,
            s3_buckets_failed=s3_buckets_failed,
            ec2_sgs_discovered=ec2_sgs_discovered,
            ec2_sgs_evaluated=ec2_sgs_evaluated,
            ec2_sgs_failed=ec2_sgs_failed,
        )

        return ScanResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            simulated=simulated,
            region=region,
            findings=all_findings,
            warnings=all_warnings,
            summary=summary,
            aws_account_id=aws_account_id,
            aws_identity_arn=aws_identity_arn,
            coverage=coverage,
        )
