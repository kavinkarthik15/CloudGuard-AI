"""
Regression tests for ScanCoverage accuracy.

All tests use mocked providers — no real AWS calls.

Coverage semantics verified:
  - s3_buckets_requested: count returned by list_s3_buckets()
  - s3_buckets_scanned:   count where analyze_s3_bucket() completed without exception
  - s3_buckets_failed:    count where analyze_s3_bucket() raised
  - ec2_sgs_discovered:   count returned by list_security_groups()
  - ec2_sgs_evaluated:    count where analyze_security_group() completed without exception
  - ec2_sgs_failed:       count where analyze_security_group() raised
  - scanned_regions:      regions that responded (even with zero SGs)
  - failed_regions:       regions that could not be contacted
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from models import (
    AclGrant,
    EncryptionConfig,
    Finding,
    InboundRule,
    PublicAccessBlockConfig,
    S3BucketConfig,
    SecurityGroupConfig,
    Severity,
    Warning,
)
from scanner import Scanner


# ---------------------------------------------------------------------------
# Helpers — mock providers
# ---------------------------------------------------------------------------

def _make_mock_provider(
    s3_buckets: list[S3BucketConfig] | None = None,
    security_groups: list[SecurityGroupConfig] | None = None,
    s3_raise: Exception | None = None,
    ec2_raise: Exception | None = None,
) -> MagicMock:
    """Build a mock ScannerProvider with controllable return values."""
    provider = MagicMock()
    if s3_raise:
        provider.list_s3_buckets.side_effect = s3_raise
    else:
        provider.list_s3_buckets.return_value = s3_buckets or []

    if ec2_raise:
        provider.list_security_groups.side_effect = ec2_raise
    else:
        provider.list_security_groups.return_value = security_groups or []

    # Remove multi-region method so the single-region path is used
    del provider.list_security_groups_multi_region
    return provider


def _clean_bucket(name: str = "clean-bucket") -> S3BucketConfig:
    """A fully locked-down S3 bucket that should produce zero findings."""
    return S3BucketConfig(
        name=name,
        region="us-east-1",
        public_access_block=PublicAccessBlockConfig(
            block_public_acls=True,
            ignore_public_acls=True,
            block_public_policy=True,
            restrict_public_buckets=True,
        ),
        acl_grants=[],
        is_public_policy=False,
        encryption=EncryptionConfig(sse_algorithm="aws:kms"),
        versioning_enabled=True,
        logging_enabled=True,
    )


def _public_bucket(name: str = "public-bucket") -> S3BucketConfig:
    """An S3 bucket that will produce a Critical finding."""
    return S3BucketConfig(
        name=name,
        region="us-east-1",
        public_access_block=PublicAccessBlockConfig(
            block_public_acls=False,
            ignore_public_acls=False,
            block_public_policy=False,
            restrict_public_buckets=False,
        ),
        acl_grants=[AclGrant(
            grantee_uri="http://acs.amazonaws.com/groups/global/AllUsers",
            permission="READ",
        )],
        is_public_policy=False,
        encryption=None,
    )


def _restricted_sg(group_id: str = "sg-clean") -> SecurityGroupConfig:
    """A security group with only private-CIDR rules — should produce zero findings."""
    return SecurityGroupConfig(
        group_id=group_id,
        group_name="internal-sg",
        description="Internal only",
        region="eu-north-1",
        inbound_rules=[
            InboundRule(
                protocol="tcp",
                from_port=443,
                to_port=443,
                cidr_ipv4="10.0.0.0/8",
                cidr_ipv6=None,
            )
        ],
    )


def _world_open_sg(group_id: str = "sg-open") -> SecurityGroupConfig:
    """A security group with SSH open to the world — produces a Critical finding."""
    return SecurityGroupConfig(
        group_id=group_id,
        group_name="open-sg",
        description="World-open",
        region="eu-north-1",
        inbound_rules=[
            InboundRule(
                protocol="tcp",
                from_port=22,
                to_port=22,
                cidr_ipv4="0.0.0.0/0",
                cidr_ipv6=None,
            )
        ],
    )


# ---------------------------------------------------------------------------
# 1. Empty S3 and EC2 results
# ---------------------------------------------------------------------------

class TestEmptyResources:
    def test_zero_s3_buckets_zero_sgs_all_counts_zero(self):
        """Scan with no S3 buckets and no SGs → all counts are zero, no warnings."""
        provider = _make_mock_provider()
        result = Scanner(provider).run(region="eu-north-1", simulated=False)

        assert result.findings == []
        assert result.warnings == []
        assert result.coverage is not None
        assert result.coverage.s3_buckets_requested == 0
        assert result.coverage.s3_buckets_scanned == 0
        assert result.coverage.s3_buckets_failed == 0
        assert result.coverage.ec2_sgs_discovered == 0
        assert result.coverage.ec2_sgs_evaluated == 0
        assert result.coverage.ec2_sgs_failed == 0
        assert result.coverage.scanned_regions == ["eu-north-1"]
        assert result.coverage.failed_regions == []

    def test_zero_resources_is_not_a_scan_failure(self):
        """Zero resources must not produce warnings — it is a valid scan outcome."""
        provider = _make_mock_provider()
        result = Scanner(provider).run(region="eu-north-1", simulated=False)
        assert result.warnings == [], f"Unexpected warnings: {result.warnings}"


# ---------------------------------------------------------------------------
# 2. One SG discovered and evaluated with zero findings
# ---------------------------------------------------------------------------

class TestOneSgZeroFindings:
    def test_restricted_sg_evaluated_not_failed(self):
        """One restricted SG → ec2_sgs_discovered=1, ec2_sgs_evaluated=1, ec2_sgs_failed=0."""
        provider = _make_mock_provider(security_groups=[_restricted_sg()])
        result = Scanner(provider).run(region="eu-north-1", simulated=False)

        assert result.findings == []
        assert result.coverage is not None
        assert result.coverage.ec2_sgs_discovered == 1
        assert result.coverage.ec2_sgs_evaluated == 1
        assert result.coverage.ec2_sgs_failed == 0
        assert result.coverage.s3_buckets_requested == 0

    def test_evaluated_region_in_scanned_regions(self):
        """Region that returned SGs (even zero findings) is in scanned_regions."""
        provider = _make_mock_provider(security_groups=[_restricted_sg()])
        result = Scanner(provider).run(region="eu-north-1", simulated=False)

        assert "eu-north-1" in result.coverage.scanned_regions
        assert result.coverage.failed_regions == []


# ---------------------------------------------------------------------------
# 3. One SG that produces a finding
# ---------------------------------------------------------------------------

class TestOneSgWithFinding:
    def test_world_open_sg_produces_finding_and_evaluated_count(self):
        """SSH 0.0.0.0/0 → Critical finding, ec2_sgs_evaluated=1, ec2_sgs_failed=0."""
        provider = _make_mock_provider(security_groups=[_world_open_sg()])
        result = Scanner(provider).run(region="eu-north-1", simulated=False)

        critical = [f for f in result.findings if f.severity == Severity.Critical]
        assert len(critical) >= 1
        assert result.coverage.ec2_sgs_discovered == 1
        assert result.coverage.ec2_sgs_evaluated == 1
        assert result.coverage.ec2_sgs_failed == 0

    def test_multiple_sgs_all_evaluated(self):
        """Two SGs (one clean, one open) → discovered=2, evaluated=2, failed=0."""
        provider = _make_mock_provider(
            security_groups=[_restricted_sg(), _world_open_sg()]
        )
        result = Scanner(provider).run(region="eu-north-1", simulated=False)

        assert result.coverage.ec2_sgs_discovered == 2
        assert result.coverage.ec2_sgs_evaluated == 2
        assert result.coverage.ec2_sgs_failed == 0


# ---------------------------------------------------------------------------
# 4. Analyzer exception → failed count increases and warning produced
# ---------------------------------------------------------------------------

class TestAnalyzerException:
    def test_ec2_analyzer_exception_increments_failed_and_produces_warning(self):
        """If analyze_security_group raises, ec2_sgs_failed++ and a Warning is added."""
        bad_sg = _restricted_sg("sg-bad")
        provider = _make_mock_provider(security_groups=[bad_sg])

        # Patch the analyzer to raise after the SG is discovered
        with patch("scanner.analyze_security_group", side_effect=RuntimeError("rule bug")):
            result = Scanner(provider).run(region="eu-north-1", simulated=False)

        assert result.coverage.ec2_sgs_discovered == 1
        assert result.coverage.ec2_sgs_evaluated == 0
        assert result.coverage.ec2_sgs_failed == 1
        # A warning must be present for the failed SG
        warning_ids = [w.resource_id for w in result.warnings]
        assert f"ec2:{bad_sg.group_id}" in warning_ids

    def test_s3_analyzer_exception_increments_failed_and_produces_warning(self):
        """If analyze_s3_bucket raises, s3_buckets_failed++ and a Warning is added."""
        bucket = _clean_bucket("bucket-problem")
        provider = _make_mock_provider(s3_buckets=[bucket])

        with patch("scanner.analyze_s3_bucket", side_effect=RuntimeError("rule bug")):
            result = Scanner(provider).run(region="eu-north-1", simulated=False)

        assert result.coverage.s3_buckets_requested == 1
        assert result.coverage.s3_buckets_scanned == 0
        assert result.coverage.s3_buckets_failed == 1
        warning_ids = [w.resource_id for w in result.warnings]
        assert f"s3:{bucket.name}" in warning_ids

    def test_good_sg_plus_bad_sg_partial_coverage(self):
        """One good SG and one that throws → evaluated=1, failed=1, finding still produced."""
        good_sg = _world_open_sg("sg-good")
        bad_sg = _restricted_sg("sg-bad")
        provider = _make_mock_provider(security_groups=[good_sg, bad_sg])

        call_count = {"n": 0}
        from analyzers.ec2_rules import analyze_security_group as real_analyze

        def patched_analyze(sg):
            call_count["n"] += 1
            if sg.group_id == "sg-bad":
                raise RuntimeError("rule crash on bad sg")
            return real_analyze(sg)

        with patch("scanner.analyze_security_group", side_effect=patched_analyze):
            result = Scanner(provider).run(region="eu-north-1", simulated=False)

        assert result.coverage.ec2_sgs_discovered == 2
        assert result.coverage.ec2_sgs_evaluated == 1
        assert result.coverage.ec2_sgs_failed == 1
        # The good SG (world-open SSH) still produced a finding
        assert len(result.findings) >= 1
        # The bad SG produced a warning
        assert any("sg-bad" in w.resource_id for w in result.warnings)


# ---------------------------------------------------------------------------
# 5. AccessDenied on resource discovery
# ---------------------------------------------------------------------------

class TestAccessDeniedDiscovery:
    def test_s3_list_access_denied_propagates_not_swallowed(self):
        """InsufficientPermissionsError from list_s3_buckets propagates out of scanner.

        The scanner catches RuntimeError but NOT InsufficientPermissionsError for S3.
        The exception propagates to _run_live_scan() which returns HTTP 403.
        This test documents and verifies that design decision — the exception is NOT
        swallowed into a Warning and is NOT presented as an empty successful scan.
        """
        from providers.boto3_provider import InsufficientPermissionsError

        provider = _make_mock_provider(
            s3_raise=InsufficientPermissionsError("s3:ListAllMyBuckets denied")
        )

        with pytest.raises(InsufficientPermissionsError):
            Scanner(provider).run(region="eu-north-1", simulated=False)

    def test_ec2_list_access_denied_propagates_not_swallowed(self):
        """InsufficientPermissionsError from list_security_groups propagates out of scanner.

        Same design: the scanner catches RuntimeError, not InsufficientPermissionsError.
        This is intentional — a scan-level permission failure should surface as an error,
        not as a zero-findings successful scan.
        """
        from providers.boto3_provider import InsufficientPermissionsError

        provider = _make_mock_provider(
            ec2_raise=InsufficientPermissionsError("ec2:DescribeSecurityGroups denied")
        )

        # S3 must succeed so we reach EC2
        provider.list_s3_buckets.return_value = []
        provider.list_s3_buckets.side_effect = None

        with pytest.raises(InsufficientPermissionsError):
            Scanner(provider).run(region="eu-north-1", simulated=False)


# ---------------------------------------------------------------------------
# 6. Coverage serialization
# ---------------------------------------------------------------------------

class TestCoverageSerialization:
    def test_coverage_serializes_to_dict_correctly(self):
        """ScanCoverage.model_dump() includes all EC2 fields."""
        provider = _make_mock_provider(security_groups=[_restricted_sg()])
        result = Scanner(provider).run(region="eu-north-1", simulated=False)

        data = result.model_dump(mode="json")
        assert data["coverage"] is not None
        cov = data["coverage"]
        assert "ec2_sgs_discovered" in cov
        assert "ec2_sgs_evaluated" in cov
        assert "ec2_sgs_failed" in cov
        assert cov["ec2_sgs_discovered"] == 1
        assert cov["ec2_sgs_evaluated"] == 1
        assert cov["ec2_sgs_failed"] == 0

    def test_coverage_included_in_json_export(self):
        """generate_json_report includes coverage with EC2 fields."""
        import json
        from report_generator import generate_json_report

        provider = _make_mock_provider(security_groups=[_restricted_sg()])
        result = Scanner(provider).run(region="eu-north-1", simulated=False)
        report_bytes = generate_json_report(result)
        report = json.loads(report_bytes)

        assert "coverage" in report
        assert report["coverage"]["ec2_sgs_discovered"] == 1
        assert report["coverage"]["ec2_sgs_evaluated"] == 1

    def test_existing_s3_coverage_still_accurate(self):
        """S3 coverage fields are unaffected by EC2 additions."""
        provider = _make_mock_provider(
            s3_buckets=[_clean_bucket("a"), _clean_bucket("b")]
        )
        result = Scanner(provider).run(region="eu-north-1", simulated=False)

        assert result.coverage.s3_buckets_requested == 2
        assert result.coverage.s3_buckets_scanned == 2
        assert result.coverage.s3_buckets_failed == 0
        assert result.coverage.ec2_sgs_discovered == 0
