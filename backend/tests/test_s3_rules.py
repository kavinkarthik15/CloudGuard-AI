"""
Unit tests for S3 misconfiguration detection rules.
All tests use inline fixture dicts — no real AWS calls.
"""
import pytest

from analyzers.s3_rules import (
    analyze_s3_bucket,
    check_effective_public_acl_or_policy,
    check_no_encryption,
    check_partial_public_access_block,
    check_sse_s3_only,
    check_versioning_disabled,
    check_logging_disabled,
)
from models import S3BucketConfig, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ALL_BLOCK_OFF = {
    "block_public_acls": False,
    "ignore_public_acls": False,
    "block_public_policy": False,
    "restrict_public_buckets": False,
}

ALL_BLOCK_ON = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}

ALL_USERS_READ = [{"grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"}]
AUTH_USERS_WRITE = [{"grantee_uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "permission": "WRITE"}]

def _bucket(**kwargs) -> S3BucketConfig:
    defaults = {
        "name": "test-bucket",
        "public_access_block": ALL_BLOCK_ON,
        "acl_grants": [],
        "is_public_policy": False,
        "encryption": None,
        "versioning_enabled": None,
        "logging_enabled": None,
    }
    defaults.update(kwargs)
    return S3BucketConfig.model_validate(defaults)


# ---------------------------------------------------------------------------
# check_effective_public_acl_or_policy
# ---------------------------------------------------------------------------

def test_critical_public_acl():
    """All block settings off + AllUsers READ ACL → Critical."""
    bucket = _bucket(public_access_block=ALL_BLOCK_OFF, acl_grants=ALL_USERS_READ)
    finding = check_effective_public_acl_or_policy(bucket)
    assert finding is not None
    assert finding.severity == Severity.Critical
    assert finding.simulated is True
    assert "simulated configuration data" in finding.risk_explanation


def test_critical_public_policy():
    """All block settings off + is_public_policy True → Critical."""
    bucket = _bucket(public_access_block=ALL_BLOCK_OFF, is_public_policy=True)
    finding = check_effective_public_acl_or_policy(bucket)
    assert finding is not None
    assert finding.severity == Severity.Critical


def test_critical_auth_users_acl():
    """AuthenticatedUsers WRITE also triggers Critical."""
    bucket = _bucket(public_access_block=ALL_BLOCK_OFF, acl_grants=AUTH_USERS_WRITE)
    finding = check_effective_public_acl_or_policy(bucket)
    assert finding is not None
    assert finding.severity == Severity.Critical


def test_no_critical_when_all_blocks_on():
    """All block settings on → no Critical finding even with public ACL."""
    bucket = _bucket(public_access_block=ALL_BLOCK_ON, acl_grants=ALL_USERS_READ)
    finding = check_effective_public_acl_or_policy(bucket)
    assert finding is None


def test_no_critical_when_no_public_acl_or_policy():
    """Block off but no public ACL or policy → not Critical (only High from partial block)."""
    partial_block = {**ALL_BLOCK_OFF}
    bucket = _bucket(public_access_block=partial_block, acl_grants=[], is_public_policy=False)
    finding = check_effective_public_acl_or_policy(bucket)
    assert finding is None


# ---------------------------------------------------------------------------
# check_partial_public_access_block
# ---------------------------------------------------------------------------

def test_high_partial_block():
    """Some block settings off, no ACL/policy exposure → High."""
    partial = {
        "block_public_acls": True,
        "ignore_public_acls": False,
        "block_public_policy": True,
        "restrict_public_buckets": False,
    }
    bucket = _bucket(public_access_block=partial)
    finding = check_partial_public_access_block(bucket)
    assert finding is not None
    assert finding.severity == Severity.High
    assert "ignore_public_acls" in str(finding.evidence)
    assert "restrict_public_buckets" in str(finding.evidence)


def test_no_partial_block_when_all_on():
    """All block settings on → no High finding."""
    bucket = _bucket(public_access_block=ALL_BLOCK_ON)
    finding = check_partial_public_access_block(bucket)
    assert finding is None


def test_no_partial_block_when_critical_applies():
    """When Critical condition is met, partial block rule returns None."""
    bucket = _bucket(public_access_block=ALL_BLOCK_OFF, acl_grants=ALL_USERS_READ)
    finding = check_partial_public_access_block(bucket)
    assert finding is None


# ---------------------------------------------------------------------------
# check_no_encryption
# ---------------------------------------------------------------------------

def test_high_no_encryption():
    """No encryption config → High."""
    bucket = _bucket(encryption=None)
    finding = check_no_encryption(bucket)
    assert finding is not None
    assert finding.severity == Severity.High
    assert finding.evidence == {"encryption": None}


def test_no_finding_when_encryption_present():
    """Any encryption config → no finding."""
    bucket = _bucket(encryption={"sse_algorithm": "AES256"})
    finding = check_no_encryption(bucket)
    assert finding is None

    bucket_kms = _bucket(encryption={"sse_algorithm": "aws:kms"})
    finding2 = check_no_encryption(bucket_kms)
    assert finding2 is None


# ---------------------------------------------------------------------------
# check_sse_s3_only
# ---------------------------------------------------------------------------

def test_informational_sse_s3():
    """SSE-S3 (AES256) → Informational."""
    bucket = _bucket(encryption={"sse_algorithm": "AES256"})
    finding = check_sse_s3_only(bucket)
    assert finding is not None
    assert finding.severity == Severity.Informational
    assert finding.evidence["sse_algorithm"] == "AES256"


def test_no_informational_for_kms():
    """SSE-KMS → no finding from this rule."""
    bucket = _bucket(encryption={"sse_algorithm": "aws:kms"})
    finding = check_sse_s3_only(bucket)
    assert finding is None


def test_no_informational_when_no_encryption():
    """No encryption → no finding from sse_s3_only rule."""
    bucket = _bucket(encryption=None)
    finding = check_sse_s3_only(bucket)
    assert finding is None


# ---------------------------------------------------------------------------
# check_versioning_disabled / check_logging_disabled
# ---------------------------------------------------------------------------

def test_low_versioning_disabled():
    bucket = _bucket(versioning_enabled=False)
    finding = check_versioning_disabled(bucket)
    assert finding is not None
    assert finding.severity == Severity.Low


def test_no_versioning_finding_when_enabled():
    bucket = _bucket(versioning_enabled=True)
    assert check_versioning_disabled(bucket) is None


def test_no_versioning_finding_when_none():
    bucket = _bucket(versioning_enabled=None)
    assert check_versioning_disabled(bucket) is None


def test_informational_logging_disabled():
    bucket = _bucket(logging_enabled=False)
    finding = check_logging_disabled(bucket)
    assert finding is not None
    assert finding.severity == Severity.Informational


# ---------------------------------------------------------------------------
# analyze_s3_bucket — integration
# ---------------------------------------------------------------------------

def test_analyze_bucket_multiple_findings():
    """Bucket with all blocks off + public ACL + no encryption → Critical + High."""
    bucket = _bucket(
        public_access_block=ALL_BLOCK_OFF,
        acl_grants=ALL_USERS_READ,
        encryption=None,
    )
    findings = analyze_s3_bucket(bucket)
    severities = {f.severity for f in findings}
    assert Severity.Critical in severities
    assert Severity.High in severities


def test_clean_bucket_no_findings():
    """Fully secure bucket → no findings."""
    bucket = _bucket(
        public_access_block=ALL_BLOCK_ON,
        acl_grants=[],
        is_public_policy=False,
        encryption={"sse_algorithm": "aws:kms"},
        versioning_enabled=True,
        logging_enabled=True,
    )
    findings = analyze_s3_bucket(bucket)
    assert findings == []


def test_all_findings_have_evidence():
    """All findings must have non-empty evidence dicts."""
    bucket = _bucket(
        public_access_block=ALL_BLOCK_OFF,
        acl_grants=ALL_USERS_READ,
        encryption={"sse_algorithm": "AES256"},
        versioning_enabled=False,
        logging_enabled=False,
    )
    findings = analyze_s3_bucket(bucket)
    assert len(findings) > 0
    for f in findings:
        assert isinstance(f.evidence, dict)
        assert len(f.evidence) > 0


def test_all_findings_simulated_true():
    """All findings must have simulated=True."""
    bucket = _bucket(
        public_access_block=ALL_BLOCK_OFF,
        acl_grants=ALL_USERS_READ,
        encryption=None,
    )
    findings = analyze_s3_bucket(bucket)
    for f in findings:
        assert f.simulated is True


def test_medium_authenticated_users_acl():
    """All blocks ON + AuthenticatedUsers ACL → Medium."""
    bucket = _bucket(
        public_access_block=ALL_BLOCK_ON,
        acl_grants=[{
            "grantee_uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            "permission": "READ"
        }],
    )
    from analyzers.s3_rules import check_authenticated_users_acl
    finding = check_authenticated_users_acl(bucket)
    assert finding is not None
    assert finding.severity == Severity.Medium


def test_no_medium_when_blocks_disabled():
    """If blocks are not all ON, the Medium rule should not fire (covered by higher rules)."""
    from analyzers.s3_rules import check_authenticated_users_acl
    bucket = _bucket(
        public_access_block=ALL_BLOCK_OFF,
        acl_grants=[{
            "grantee_uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            "permission": "READ"
        }],
    )
    finding = check_authenticated_users_acl(bucket)
    assert finding is None
