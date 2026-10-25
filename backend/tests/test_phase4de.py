"""
Phase 4D and 4E regression tests.

Phase 4D — S3 Region-Aware Scanning:
  - null LocationConstraint → us-east-1
  - 'EU' LocationConstraint → eu-west-1
  - Bucket in eu-west-1 uses eu-west-1 regional client
  - AccessDenied on get_bucket_location → Warning, fallback to us-east-1
  - NoSuchBucket on get_bucket_location → Warning, fallback to us-east-1
  - Regional client is cached (same client reused for same region)
  - S3BucketConfig carries correct region field
  - Bucket region included in finding evidence
  - Existing S3 rule regression: all rules still fire correctly

Phase 4E — Multi-Region EC2 Scanning:
  - Single region backward compatibility
  - Two regions: findings from both regions returned
  - Duplicate region deduplicated
  - Per-region AccessDenied adds warning and continues
  - ALL_ENABLED sentinel triggers describe_regions
  - Pagination: multiple pages handled correctly
  - SecurityGroupConfig carries correct region field
  - Region included in finding evidence
  - ScanResult.coverage populated
  - Scanner.run() with regions= parameter

All tests are MOCKED — no live AWS calls.
"""
from __future__ import annotations

import pytest
import botocore.exceptions
from unittest.mock import MagicMock, patch, call

from models import (
    S3BucketConfig,
    SecurityGroupConfig,
    PublicAccessBlockConfig,
    ScanRequest,
    Warning,
)
from providers.boto3_provider import (
    Boto3ScannerProvider,
    InsufficientPermissionsError,
    SessionExpiredError,
    MissingCredentialsError,
)
from scanner import Scanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_provider(profile: str = "test", region: str = "eu-north-1") -> Boto3ScannerProvider:
    """Create a Boto3ScannerProvider with a mocked boto3.Session."""
    with patch("providers.boto3_provider.boto3.Session") as mock_cls:
        mock_session = MagicMock()
        mock_session.get_credentials.return_value = MagicMock()
        mock_cls.return_value = mock_session
        provider = Boto3ScannerProvider(profile_name=profile, region=region)
    provider._session = MagicMock()
    return provider


def _client_error(code: str, msg: str = "test") -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": msg}},
        "TestOperation",
    )


def _make_sg_response(group_id: str = "sg-abc", region: str = "eu-north-1") -> dict:
    return {
        "SecurityGroups": [{
            "GroupId": group_id,
            "GroupName": f"test-sg-{group_id}",
            "Description": "test",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
            "VpcId": "vpc-test",
        }]
    }


# ===========================================================================
# PHASE 4D — S3 Region-Aware Scanning
# ===========================================================================

class TestS3BucketRegionDiscovery:

    def test_null_location_constraint_maps_to_us_east_1(self):
        """LocationConstraint=None → bucket region is us-east-1 (AWS legacy behaviour)."""
        provider = _make_provider()

        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "my-bucket"}]}
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}
        # Stub all per-attribute calls
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
        mock_s3.get_bucket_encryption.side_effect = _client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_s3.get_bucket_logging.return_value = {}
        provider._session.client.return_value = mock_s3

        configs = provider.list_s3_buckets()

        assert len(configs) == 1
        assert configs[0].region == "us-east-1"
        mock_s3.get_bucket_location.assert_called_once_with(Bucket="my-bucket")

    def test_empty_string_location_constraint_maps_to_us_east_1(self):
        """LocationConstraint='' → bucket region is us-east-1."""
        provider = _make_provider()
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "bucket-x"}]}
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": ""}
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
        mock_s3.get_bucket_encryption.side_effect = _client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        mock_s3.get_bucket_versioning.return_value = {}
        mock_s3.get_bucket_logging.return_value = {}
        provider._session.client.return_value = mock_s3

        configs = provider.list_s3_buckets()
        assert configs[0].region == "us-east-1"

    def test_eu_alias_maps_to_eu_west_1(self):
        """Legacy LocationConstraint='EU' → eu-west-1."""
        provider = _make_provider()
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "eu-bucket"}]}
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": "EU"}
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
        mock_s3.get_bucket_encryption.side_effect = _client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        mock_s3.get_bucket_versioning.return_value = {}
        mock_s3.get_bucket_logging.return_value = {}
        provider._session.client.return_value = mock_s3

        configs = provider.list_s3_buckets()
        assert configs[0].region == "eu-west-1"

    def test_bucket_in_eu_west_1_uses_regional_client(self):
        """A bucket in eu-west-1 should trigger creation of an eu-west-1 S3 client."""
        provider = _make_provider()

        # Track client() calls
        client_calls: list[dict] = []

        def mock_client_factory(service, region_name=None):
            client_calls.append({"service": service, "region": region_name})
            mock_s3 = MagicMock()
            mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "eu-bucket"}]}
            mock_s3.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}
            mock_s3.get_bucket_public_access_block.return_value = {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True, "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                }
            }
            mock_s3.get_bucket_acl.return_value = {"Grants": []}
            mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
            mock_s3.get_bucket_encryption.side_effect = _client_error(
                "ServerSideEncryptionConfigurationNotFoundError"
            )
            mock_s3.get_bucket_versioning.return_value = {}
            mock_s3.get_bucket_logging.return_value = {}
            return mock_s3

        provider._session.client.side_effect = mock_client_factory

        provider.list_s3_buckets()

        # First call is us-east-1 (global listing)
        assert client_calls[0] == {"service": "s3", "region": "us-east-1"}
        # Second call creates regional client for eu-west-1
        regional_calls = [c for c in client_calls if c["region"] == "eu-west-1"]
        assert len(regional_calls) == 1, "Expected exactly one eu-west-1 regional client"

    def test_regional_client_cached_for_same_region(self):
        """Two buckets in the same region should share one regional client (not two)."""
        provider = _make_provider()
        client_calls: list[str] = []

        def mock_client_factory(service, region_name=None):
            client_calls.append(region_name)
            mock_s3 = MagicMock()
            mock_s3.list_buckets.return_value = {
                "Buckets": [{"Name": "bucket-a"}, {"Name": "bucket-b"}]
            }
            mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-southeast-1"}
            mock_s3.get_bucket_public_access_block.return_value = {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True, "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                }
            }
            mock_s3.get_bucket_acl.return_value = {"Grants": []}
            mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
            mock_s3.get_bucket_encryption.side_effect = _client_error(
                "ServerSideEncryptionConfigurationNotFoundError"
            )
            mock_s3.get_bucket_versioning.return_value = {}
            mock_s3.get_bucket_logging.return_value = {}
            return mock_s3

        provider._session.client.side_effect = mock_client_factory

        provider.list_s3_buckets()

        # Should have: 1 call for us-east-1 (global) + 1 call for ap-southeast-1 (cached)
        ap_calls = [c for c in client_calls if c == "ap-southeast-1"]
        assert len(ap_calls) == 1, (
            f"Expected 1 ap-southeast-1 client (cached), got {len(ap_calls)}"
        )

    def test_access_denied_on_get_bucket_location_produces_warning(self):
        """AccessDenied on get_bucket_location → Warning added, fallback to us-east-1."""
        provider = _make_provider()
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "locked-bucket"}]}
        mock_s3.get_bucket_location.side_effect = _client_error("AccessDenied")
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
        mock_s3.get_bucket_encryption.side_effect = _client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        mock_s3.get_bucket_versioning.return_value = {}
        mock_s3.get_bucket_logging.return_value = {}
        provider._session.client.return_value = mock_s3

        configs = provider.list_s3_buckets()

        assert len(configs) == 1
        # Falls back to us-east-1
        assert configs[0].region == "us-east-1"
        # Warning is attached via typed scan_warnings field
        warnings = configs[0].scan_warnings
        assert len(warnings) >= 1
        assert any("AccessDenied" in w.reason or "location" in w.resource_id for w in warnings)
        # Must NOT report the bucket as clean — the warning signals unknown state
        assert any("NOT confirmed secure" in w.reason for w in warnings)

    def test_no_such_bucket_on_get_bucket_location_produces_warning(self):
        """NoSuchBucket on get_bucket_location → Warning added, skip remaining calls."""
        provider = _make_provider()
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "ghost-bucket"}]}
        mock_s3.get_bucket_location.side_effect = _client_error("NoSuchBucket")
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
        mock_s3.get_bucket_encryption.side_effect = _client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        mock_s3.get_bucket_versioning.return_value = {}
        mock_s3.get_bucket_logging.return_value = {}
        provider._session.client.return_value = mock_s3

        configs = provider.list_s3_buckets()
        assert len(configs) == 1
        # Warning is attached via typed scan_warnings field
        warnings = configs[0].scan_warnings
        assert len(warnings) >= 1
        assert any("NoSuchBucket" in w.reason or "no longer exists" in w.reason for w in warnings)

    def test_bucket_region_stored_in_s3bucketconfig(self):
        """S3BucketConfig.region reflects the actual bucket region."""
        provider = _make_provider()
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "ap-bucket"}]}
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-northeast-1"}
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
        mock_s3.get_bucket_encryption.side_effect = _client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        mock_s3.get_bucket_versioning.return_value = {}
        mock_s3.get_bucket_logging.return_value = {}
        provider._session.client.return_value = mock_s3

        configs = provider.list_s3_buckets()
        assert configs[0].region == "ap-northeast-1"

    def test_bucket_region_in_finding_evidence(self):
        """Scanner injects bucket_region into finding evidence."""
        from providers.simulated import SimulatedScannerProvider

        # Use simulated provider (default region=us-east-1)
        scanner = Scanner(SimulatedScannerProvider())
        result = scanner.run(simulated=True)

        # Every S3 finding should have bucket_region in evidence
        s3_findings = [f for f in result.findings if f.resource_type == "S3Bucket"]
        assert len(s3_findings) > 0
        for f in s3_findings:
            assert "bucket_region" in f.evidence, (
                f"Finding {f.id} for bucket '{f.resource_name}' missing bucket_region in evidence"
            )


# ===========================================================================
# PHASE 4E — Multi-Region EC2 Scanning
# ===========================================================================

class TestEc2MultiRegionScanning:

    def test_single_region_backward_compat(self):
        """list_security_groups with one region works exactly as before."""
        provider = _make_provider()
        mock_ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [_make_sg_response("sg-001", "eu-north-1")]
        mock_ec2.get_paginator.return_value = paginator
        provider._session.client.return_value = mock_ec2

        sgs = provider.list_security_groups("eu-north-1")

        assert len(sgs) == 1
        assert sgs[0].group_id == "sg-001"
        assert sgs[0].region == "eu-north-1"

    def test_security_group_carries_region_field(self):
        """list_security_groups tags each SecurityGroupConfig with the scanned region."""
        provider = _make_provider()
        mock_ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [_make_sg_response("sg-xyz", "us-west-2")]
        mock_ec2.get_paginator.return_value = paginator
        provider._session.client.return_value = mock_ec2

        sgs = provider.list_security_groups("us-west-2")
        assert sgs[0].region == "us-west-2"

    def test_multi_region_returns_findings_from_all_regions(self):
        """list_security_groups_multi_region returns SGs from both requested regions."""
        provider = _make_provider()

        def client_factory(service, region_name=None):
            mock_ec2 = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [_make_sg_response(f"sg-{region_name}", region_name)]
            mock_ec2.get_paginator.return_value = paginator
            return mock_ec2

        provider._session.client.side_effect = client_factory

        sgs, scanned, warnings = provider.list_security_groups_multi_region(
            ["eu-north-1", "us-east-1"]
        )

        assert len(sgs) == 2
        regions = {sg.region for sg in sgs}
        assert "eu-north-1" in regions
        assert "us-east-1" in regions
        assert len(warnings) == 0
        assert set(scanned) == {"eu-north-1", "us-east-1"}

    def test_duplicate_regions_deduplicated(self):
        """Passing the same region twice produces only one scan."""
        provider = _make_provider()
        scan_calls: list[str] = []

        def client_factory(service, region_name=None):
            scan_calls.append(region_name)
            mock_ec2 = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [_make_sg_response("sg-dup", region_name)]
            mock_ec2.get_paginator.return_value = paginator
            return mock_ec2

        provider._session.client.side_effect = client_factory

        sgs, scanned, warnings = provider.list_security_groups_multi_region(
            ["eu-north-1", "eu-north-1", "eu-north-1"]
        )

        eu_scans = [c for c in scan_calls if c == "eu-north-1"]
        assert len(eu_scans) == 1, f"Expected 1 scan of eu-north-1, got {len(eu_scans)}"
        assert len(sgs) == 1
        assert scanned == ["eu-north-1"]

    def test_per_region_access_denied_adds_warning_and_continues(self):
        """AccessDenied in one region adds a warning but other regions still scanned."""
        provider = _make_provider()

        def client_factory(service, region_name=None):
            mock_ec2 = MagicMock()
            if region_name == "eu-central-1":
                # Denied region — paginator raises on paginate()
                paginator = MagicMock()
                paginator.paginate.side_effect = _client_error("AccessDenied")
                mock_ec2.get_paginator.return_value = paginator
            else:
                paginator = MagicMock()
                paginator.paginate.return_value = [_make_sg_response("sg-ok", region_name)]
                mock_ec2.get_paginator.return_value = paginator
            return mock_ec2

        provider._session.client.side_effect = client_factory

        sgs, scanned, warnings = provider.list_security_groups_multi_region(
            ["eu-north-1", "eu-central-1", "us-east-1"]
        )

        # Two regions succeeded, one failed
        assert len(sgs) == 2
        assert len(warnings) == 1
        assert "eu-central-1" in warnings[0].resource_id
        # eu-north-1 and us-east-1 are in scanned; eu-central-1 is not
        assert "eu-central-1" not in scanned
        assert "eu-north-1" in scanned
        assert "us-east-1" in scanned

    def test_all_enabled_sentinel_calls_describe_regions(self):
        """ALL_ENABLED sentinel triggers ec2:DescribeRegions call."""
        provider = _make_provider(region="eu-north-1")

        with patch("providers.boto3_provider.list_enabled_regions") as mock_list_enabled:
            mock_list_enabled.return_value = (["eu-north-1"], None)

            def client_factory(service, region_name=None):
                mock_ec2 = MagicMock()
                paginator = MagicMock()
                paginator.paginate.return_value = [_make_sg_response("sg-enabled", region_name)]
                mock_ec2.get_paginator.return_value = paginator
                return mock_ec2

            provider._session.client.side_effect = client_factory

            sgs, scanned, warnings = provider.list_security_groups_multi_region(["ALL_ENABLED"])

        mock_list_enabled.assert_called_once()
        assert len(sgs) == 1
        assert sgs[0].region == "eu-north-1"
        assert "eu-north-1" in scanned

    def test_all_enabled_falls_back_on_describe_regions_error(self):
        """If describe_regions fails, falls back to botocore known regions."""
        provider = _make_provider(region="eu-north-1")

        with patch("providers.boto3_provider.list_enabled_regions") as mock_enabled, \
             patch("providers.boto3_provider.list_known_regions") as mock_known:
            mock_enabled.return_value = ([], "AccessDenied")
            mock_known.return_value = ["eu-north-1", "us-east-1"]

            call_count = {"n": 0}

            def client_factory(service, region_name=None):
                call_count["n"] += 1
                mock_ec2 = MagicMock()
                paginator = MagicMock()
                paginator.paginate.return_value = []
                mock_ec2.get_paginator.return_value = paginator
                return mock_ec2

            provider._session.client.side_effect = client_factory

            sgs, scanned, warnings = provider.list_security_groups_multi_region(["ALL_ENABLED"])

        mock_known.assert_called_once()
        # Should have attempted both known regions
        assert call_count["n"] >= 2
        # Both regions were successfully scanned (even with empty SG lists)
        assert set(scanned) == {"eu-north-1", "us-east-1"}

    def test_pagination_handled_for_describe_security_groups(self):
        """DescribeSecurityGroups paginator iterates multiple pages."""
        provider = _make_provider()
        mock_ec2 = MagicMock()
        paginator = MagicMock()
        # Two pages of results
        paginator.paginate.return_value = [
            _make_sg_response("sg-page1-a", "eu-north-1"),
            {"SecurityGroups": [{
                "GroupId": "sg-page2-b",
                "GroupName": "page2-sg",
                "Description": "page 2",
                "IpPermissions": [],
                "VpcId": "vpc-x",
            }]},
        ]
        mock_ec2.get_paginator.return_value = paginator
        provider._session.client.return_value = mock_ec2

        sgs = provider.list_security_groups("eu-north-1")
        assert len(sgs) == 2
        ids = {sg.group_id for sg in sgs}
        assert "sg-page1-a" in ids
        assert "sg-page2-b" in ids

    def test_region_in_ec2_finding_evidence(self):
        """Scanner injects region into EC2 security group finding evidence."""
        from providers.simulated import SimulatedScannerProvider

        scanner = Scanner(SimulatedScannerProvider())
        result = scanner.run(region="ap-southeast-1", simulated=True)

        ec2_findings = [f for f in result.findings if f.resource_type == "SecurityGroup"]
        assert len(ec2_findings) > 0
        for f in ec2_findings:
            assert "region" in f.evidence, (
                f"Finding {f.id} for SG '{f.resource_name}' missing region in evidence"
            )

    def test_scanner_run_with_regions_parameter(self):
        """Scanner.run() with regions= produces coverage metadata."""
        from providers.simulated import SimulatedScannerProvider

        scanner = Scanner(SimulatedScannerProvider())
        result = scanner.run(
            region="eu-north-1",
            regions=["eu-north-1", "us-east-1"],
            simulated=True,
        )

        assert result.coverage is not None
        assert "eu-north-1" in result.coverage.requested_regions
        assert "us-east-1" in result.coverage.requested_regions

    def test_scan_coverage_populated_in_result(self):
        """ScanResult.coverage has correct s3 and ec2 counts."""
        from providers.simulated import SimulatedScannerProvider

        scanner = Scanner(SimulatedScannerProvider())
        result = scanner.run(simulated=True)

        assert result.coverage is not None
        assert result.coverage.s3_buckets_requested >= 0
        assert result.coverage.s3_buckets_scanned >= 0
        assert result.coverage.s3_buckets_failed >= 0

    def test_multi_region_no_duplicates_same_sg_different_regions(self):
        """Security groups from different regions with same ID don't collide."""
        provider = _make_provider()

        def client_factory(service, region_name=None):
            mock_ec2 = MagicMock()
            paginator = MagicMock()
            # Same group ID in both regions (realistic — SG IDs are regional)
            paginator.paginate.return_value = [_make_sg_response("sg-same-id", region_name)]
            mock_ec2.get_paginator.return_value = paginator
            return mock_ec2

        provider._session.client.side_effect = client_factory

        sgs, scanned, warnings = provider.list_security_groups_multi_region(["eu-north-1", "us-east-1"])

        assert len(sgs) == 2
        # Both should be present — same ID but different regions
        regions = {sg.region for sg in sgs}
        assert "eu-north-1" in regions
        assert "us-east-1" in regions
        # Both regions are in scanned (zero failures)
        assert set(scanned) == {"eu-north-1", "us-east-1"}
        assert warnings == []


# ===========================================================================
# Regression: existing S3 and EC2 rules still fire correctly
# ===========================================================================

class TestExistingRulesRegression:

    def test_s3_public_bucket_still_detected(self):
        """Phase 4D changes must not break Critical S3 public access detection."""
        config = S3BucketConfig(
            name="public-bucket",
            region="eu-west-1",
            public_access_block=PublicAccessBlockConfig(
                block_public_acls=False, ignore_public_acls=False,
                block_public_policy=False, restrict_public_buckets=False,
            ),
            acl_grants=[],
            is_public_policy=True,
            encryption=None,
        )
        from analyzers.s3_rules import analyze_s3_bucket
        findings = analyze_s3_bucket(config)
        severities = {f.severity.value for f in findings}
        assert "Critical" in severities

    def test_ec2_ssh_open_still_detected(self):
        """Phase 4E changes must not break Critical EC2 SSH detection."""
        from models import InboundRule
        from analyzers.ec2_rules import analyze_security_group
        sg = SecurityGroupConfig(
            group_id="sg-test",
            group_name="test-sg",
            description="test",
            region="us-east-1",
            inbound_rules=[
                InboundRule(
                    protocol="tcp", from_port=22, to_port=22,
                    cidr_ipv4="0.0.0.0/0", cidr_ipv6=None,
                )
            ],
        )
        findings = analyze_security_group(sg)
        assert any(f.severity.value == "Critical" for f in findings)

    def test_s3bucketconfig_default_region_is_us_east_1(self):
        """Existing code creating S3BucketConfig without region= still works."""
        config = S3BucketConfig(
            name="legacy-bucket",
            public_access_block=PublicAccessBlockConfig(
                block_public_acls=True, ignore_public_acls=True,
                block_public_policy=True, restrict_public_buckets=True,
            ),
        )
        assert config.region == "us-east-1"

    def test_securitygroupconfig_default_region_is_us_east_1(self):
        """Existing code creating SecurityGroupConfig without region= still works."""
        sg = SecurityGroupConfig(
            group_id="sg-legacy",
            group_name="legacy",
            description="legacy",
        )
        assert sg.region == "us-east-1"


# ===========================================================================
# Phase 4E correctness: empty region counted as successfully scanned
# ===========================================================================

class TestEmptyRegionCounting:
    """A region that returns zero security groups is NOT a failure.

    This validates the fix to the coverage accuracy bug: scanned_regions must
    be populated from explicit tracking (per-attempt success flag), not derived
    from returned SG objects (which would exclude empty regions).
    """

    def test_empty_region_counted_in_scanned_not_failed(self):
        """Region returning zero SGs counts as scanned, not failed."""
        provider = _make_provider()

        def client_factory(service, region_name=None):
            mock_ec2 = MagicMock()
            paginator = MagicMock()
            # eu-north-1 has SGs; ap-east-1 has none (empty paginator)
            if region_name == "ap-east-1":
                paginator.paginate.return_value = [{"SecurityGroups": []}]
            else:
                paginator.paginate.return_value = [_make_sg_response("sg-ok", region_name)]
            mock_ec2.get_paginator.return_value = paginator
            return mock_ec2

        provider._session.client.side_effect = client_factory

        sgs, scanned, warnings = provider.list_security_groups_multi_region(
            ["eu-north-1", "ap-east-1"]
        )

        # eu-north-1 returned one SG; ap-east-1 returned zero — but both succeeded
        assert len(sgs) == 1
        assert sgs[0].region == "eu-north-1"
        assert "eu-north-1" in scanned, "eu-north-1 should be in scanned (had SGs)"
        assert "ap-east-1" in scanned, "ap-east-1 should be in scanned (zero SGs is not a failure)"
        assert warnings == [], "No warnings expected — both regions responded without error"

    def test_scanner_coverage_counts_empty_region_as_scanned(self):
        """Scanner.coverage.scanned_regions includes an empty region."""
        from unittest.mock import MagicMock, patch

        # Build a mock provider that supports multi-region and returns an empty region
        mock_provider = MagicMock()
        mock_provider.list_s3_buckets.return_value = []
        # Simulate provider returning: eu-north-1 (1 SG), us-west-2 (0 SGs), no warnings
        from models import SecurityGroupConfig, InboundRule
        sg_in_eu = SecurityGroupConfig(
            group_id="sg-eu-1",
            group_name="sg-eu",
            description="eu sg",
            region="eu-north-1",
            inbound_rules=[],
        )
        mock_provider.list_security_groups_multi_region.return_value = (
            [sg_in_eu],           # SGs (only eu-north-1 has one)
            ["eu-north-1", "us-west-2"],  # scanned (both regions attempted and succeeded)
            [],                   # warnings
        )

        scanner = Scanner(mock_provider)
        result = scanner.run(
            region="eu-north-1",
            regions=["eu-north-1", "us-west-2"],
            simulated=True,
        )

        assert result.coverage is not None
        assert "eu-north-1" in result.coverage.scanned_regions
        assert "us-west-2" in result.coverage.scanned_regions, (
            "us-west-2 returned zero SGs but was successfully contacted — "
            "it must appear in scanned_regions, not failed_regions"
        )
        assert "us-west-2" not in result.coverage.failed_regions
        assert result.coverage.failed_regions == []


# ===========================================================================
# Phase 4D correctness: S3 scan_warnings survive into ScanResult
# ===========================================================================

class TestS3WarningPropagation:
    """S3 per-bucket warnings from Boto3ScannerProvider must reach ScanResult.warnings.

    This validates the typed `scan_warnings` field mechanism: warnings set by
    the provider are drained by the scanner and added to ScanResult.warnings,
    where the API serialises them as part of the response body.
    """

    def test_s3_scan_warnings_reach_scan_result(self):
        """Per-bucket scan_warnings are drained into ScanResult.warnings."""
        from models import S3BucketConfig, PublicAccessBlockConfig, Warning

        # Build a bucket config with a pre-populated scan_warnings field
        bucket_with_warning = S3BucketConfig(
            name="warned-bucket",
            region="us-east-1",
            public_access_block=PublicAccessBlockConfig(
                block_public_acls=True, ignore_public_acls=True,
                block_public_policy=True, restrict_public_buckets=True,
            ),
            scan_warnings=[
                Warning(
                    resource_id="s3:warned-bucket:location",
                    reason="AccessDenied — s3:GetBucketLocation. Region unknown; bucket is NOT confirmed secure.",
                )
            ],
        )

        mock_provider = MagicMock()
        mock_provider.list_s3_buckets.return_value = [bucket_with_warning]
        mock_provider.list_security_groups.return_value = []

        scanner = Scanner(mock_provider)
        result = scanner.run(simulated=True)

        # The warning must appear in ScanResult.warnings
        warning_ids = [w.resource_id for w in result.warnings]
        assert "s3:warned-bucket:location" in warning_ids, (
            "Per-bucket scan_warnings must be propagated into ScanResult.warnings"
        )

    def test_s3_access_denied_on_location_warning_survives_to_api(self):
        """End-to-end: AccessDenied on GetBucketLocation → warning in ScanResult."""
        provider = _make_provider()
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "inaccessible-bucket"}]}
        mock_s3.get_bucket_location.side_effect = _client_error("AccessDenied")
        # All attribute calls succeed (we still proceed after region fallback)
        mock_s3.get_bucket_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_policy_status.side_effect = _client_error("NoSuchBucketPolicy")
        mock_s3.get_bucket_encryption.side_effect = _client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_s3.get_bucket_logging.return_value = {"LoggingEnabled": {}}
        provider._session.client.return_value = mock_s3

        # Override list_security_groups so scanner can complete
        mock_ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = []
        mock_ec2.get_paginator.return_value = paginator

        def client_factory(service, region_name=None):
            if service == "s3":
                return mock_s3
            return mock_ec2

        provider._session.client.side_effect = client_factory

        scanner = Scanner(provider)
        result = scanner.run(simulated=False)

        # The AccessDenied warning must appear in the ScanResult
        location_warnings = [
            w for w in result.warnings
            if "inaccessible-bucket" in w.resource_id and "location" in w.resource_id
        ]
        assert len(location_warnings) >= 1, (
            "AccessDenied on GetBucketLocation must produce a warning in ScanResult"
        )
        assert any("NOT confirmed secure" in w.reason for w in location_warnings), (
            "Warning must state the bucket is NOT confirmed secure, not silently treat it as clean"
        )

    def test_scan_warnings_field_is_excluded_from_serialization(self):
        """S3BucketConfig.scan_warnings must not appear in model JSON output.

        scan_warnings is scan-quality metadata for internal use by the scanner.
        It must not leak into API responses or exports.
        """
        from models import S3BucketConfig, PublicAccessBlockConfig, Warning

        config = S3BucketConfig(
            name="test-bucket",
            region="us-east-1",
            public_access_block=PublicAccessBlockConfig(
                block_public_acls=True, ignore_public_acls=True,
                block_public_policy=True, restrict_public_buckets=True,
            ),
            scan_warnings=[
                Warning(resource_id="s3:test-bucket:location", reason="test warning")
            ],
        )

        serialized = config.model_dump()
        assert "scan_warnings" not in serialized, (
            "scan_warnings is excluded=True — it must not appear in model_dump() output"
        )

        json_str = config.model_dump_json()
        assert "scan_warnings" not in json_str, (
            "scan_warnings must not appear in JSON serialization"
        )
