"""
Pydantic v2 data models for CloudGuard AI.

Session 1: All models used for simulated resource configurations.
Session 2: ScanMode, IdentityInfo, and ScanResult.aws_account_id added for live AWS scanning.
No AWS credentials are ever stored in or passed through these models.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Risk classification for a Finding. Reflects configuration risk,
    not confirmed exploitability."""
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"
    Informational = "Informational"


SEVERITY_ORDER = [
    Severity.Critical,
    Severity.High,
    Severity.Medium,
    Severity.Low,
    Severity.Informational,
]


# ---------------------------------------------------------------------------
# S3 resource configuration models
# ---------------------------------------------------------------------------

class PublicAccessBlockConfig(BaseModel):
    """Represents the four S3 Block Public Access settings."""
    block_public_acls: bool
    ignore_public_acls: bool
    block_public_policy: bool
    restrict_public_buckets: bool

    @property
    def all_enabled(self) -> bool:
        return (
            self.block_public_acls
            and self.ignore_public_acls
            and self.block_public_policy
            and self.restrict_public_buckets
        )

    @property
    def any_disabled(self) -> bool:
        return not self.all_enabled

    def disabled_settings(self) -> list[str]:
        """Return names of disabled settings."""
        result = []
        if not self.block_public_acls:
            result.append("block_public_acls")
        if not self.ignore_public_acls:
            result.append("ignore_public_acls")
        if not self.block_public_policy:
            result.append("block_public_policy")
        if not self.restrict_public_buckets:
            result.append("restrict_public_buckets")
        return result


class AclGrant(BaseModel):
    """A single ACL grant entry on an S3 bucket."""
    grantee_uri: str
    permission: str


class EncryptionConfig(BaseModel):
    """Server-side encryption configuration for an S3 bucket."""
    sse_algorithm: str  # "AES256" or "aws:kms"
    kms_key_id: Optional[str] = None


class Warning(BaseModel):
    """A resource that could not be fully scanned, with the reason.
    Defined here (before S3BucketConfig) so S3BucketConfig.scan_warnings
    can reference it without a forward reference.
    """
    resource_id: str
    reason: str


class S3BucketConfig(BaseModel):
    """S3 bucket configuration for security analysis.
    Used by both SimulatedScannerProvider (Session 1) and Boto3ScannerProvider (Session 2).
    """
    name: str
    public_access_block: PublicAccessBlockConfig
    acl_grants: list[AclGrant] = Field(default_factory=list)
    is_public_policy: bool = False
    encryption: Optional[EncryptionConfig] = None
    versioning_enabled: Optional[bool] = None
    logging_enabled: Optional[bool] = None
    # Phase 4D: actual AWS region of the bucket (null LocationConstraint = us-east-1)
    region: str = "us-east-1"
    # Phase 4D: per-bucket warnings from regional client work (e.g. AccessDenied on
    # GetBucketLocation). Not a security finding — carries scan-quality metadata.
    # Excluded from serialization to avoid polluting API responses directly;
    # Scanner drains these and adds them to ScanResult.warnings.
    scan_warnings: list[Warning] = Field(default_factory=list, exclude=True)


# ---------------------------------------------------------------------------
# EC2 security group resource configuration models
# ---------------------------------------------------------------------------

class InboundRule(BaseModel):
    """A single inbound rule in an EC2 security group."""
    protocol: str            # "tcp", "udp", "-1" (all traffic)
    from_port: Optional[int] = None
    to_port: Optional[int] = None
    cidr_ipv4: Optional[str] = None
    cidr_ipv6: Optional[str] = None
    description: Optional[str] = None


class SecurityGroupConfig(BaseModel):
    """EC2 security group configuration for security analysis.
    Used by both SimulatedScannerProvider (Session 1) and Boto3ScannerProvider (Session 2).
    """
    group_id: str
    group_name: str
    description: str
    inbound_rules: list[InboundRule] = Field(default_factory=list)
    vpc_id: Optional[str] = None
    # Phase 4E: the AWS region this security group belongs to
    region: str = "us-east-1"


# ---------------------------------------------------------------------------
# Finding and scan result models
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A single identified security misconfiguration produced by the Analyzer."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_type: str          # "S3Bucket" | "SecurityGroup"
    resource_name: str
    severity: Severity
    title: str
    evidence: dict              # Specific config values that triggered the rule
    risk_explanation: str
    remediation: str
    simulated: bool = True      # False for live AWS findings


class ScanCoverage(BaseModel):
    """Coverage metadata for Phase 4D/4E — what was requested vs actually scanned.

    All fields are optional so existing clients that don't use coverage are unaffected.
    """
    # EC2 multi-region coverage
    requested_regions: list[str] = Field(default_factory=list)
    scanned_regions: list[str] = Field(default_factory=list)
    failed_regions: list[str] = Field(default_factory=list)
    # S3 coverage
    s3_buckets_requested: int = 0
    s3_buckets_scanned: int = 0
    s3_buckets_failed: int = 0


class ScanResult(BaseModel):
    """Complete result of a Scan_Session."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    simulated: bool = True
    region: str = "us-east-1"
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[Warning] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    # Session 2: live scan identity metadata — None for simulated scans.
    # Never populated with raw credentials or session tokens.
    aws_account_id: Optional[str] = None
    aws_identity_arn: Optional[str] = None
    # Phase 4D/4E: scan coverage metadata (optional — backward compatible)
    coverage: Optional[ScanCoverage] = None


# ---------------------------------------------------------------------------
# API request / response models
# ---------------------------------------------------------------------------

class ScanMode(str, Enum):
    """Explicit per-request scan mode.

    demo: Uses SimulatedScannerProvider with JSON fixtures. No AWS credentials needed.
    live: Uses Boto3ScannerProvider with real AWS APIs. Requires a valid SSO session.

    The mode is declared by the caller on every request. The backend never
    infers mode from a previous request or falls back silently.
    """
    demo = "demo"
    live = "live"


class ScanRequest(BaseModel):
    """Request body for POST /api/scan."""
    region: str = "us-east-1"
    # Phase 4E: optional multi-region list. When supplied, all entries are scanned.
    # Single-region mode (backward compat): omit 'regions' and use 'region'.
    # All-enabled mode: set regions=["ALL_ENABLED"].
    regions: Optional[list[str]] = None
    mode: ScanMode = ScanMode.demo
    aws_profile: Optional[str] = None
    # Optional profile override for live mode. Defaults to AWS_PROFILE env var
    # or the standard 'default' profile if neither is set. Ignored for demo mode.
    # Never persisted or logged by the backend.


class IdentityInfo(BaseModel):
    """AWS caller identity — returned by GET /api/identity.
    Contains only account/identity metadata, never credentials or tokens.
    """
    account_id: str
    arn: str
    user_id: str
    region: str
    profile: Optional[str] = None


class ErrorResponse(BaseModel):
    """Standard structured error response body."""
    code: str
    message: str


class ProfilesResponse(BaseModel):
    """AWS CLI profiles discovered on the local machine.

    Contains profile names only — no credential values, file paths,
    or secrets are included.
    """
    profiles: list[str]
    default_profile: Optional[str]  # AWS_PROFILE env var value, if set and non-empty
    discovery_error: Optional[str] = None  # set if botocore config was unreadable


class RegionInfo(BaseModel):
    """Metadata about a single AWS region."""
    name: str            # e.g. "eu-north-1"
    description: str     # human-readable label, e.g. "Europe (Stockholm)"
    # True = account has opted in (or region requires no opt-in).
    # False = account has NOT opted in.
    # None = availability could not be determined (DescribeRegions not called or failed).
    enabled: Optional[bool] = None


class RegionsResponse(BaseModel):
    """AWS regions available for EC2 security group scanning.

    known_regions is sourced from botocore endpoint metadata and is always
    populated without making any AWS API call.

    enabled_regions is populated only when ec2:DescribeRegions succeeds
    for the given profile. If the call fails or was not attempted,
    enabled_regions_available is False and known_regions should be used.

    Note: S3 scanning is always global and is not affected by region selection.
    """
    regions: list[RegionInfo]
    enabled_regions_available: bool  # True if DescribeRegions was called successfully
    default_region: str              # backend default (AWS_DEFAULT_REGION or eu-north-1)
    describe_regions_error: Optional[str] = None  # human-readable if DescribeRegions failed
