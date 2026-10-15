"""
Pydantic v2 data models for CloudGuard AI Session 1.
All models are used for simulated resource configurations and findings.
No real AWS credentials or API calls are involved.
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


class S3BucketConfig(BaseModel):
    """Simulated S3 bucket configuration for security analysis."""
    name: str
    public_access_block: PublicAccessBlockConfig
    acl_grants: list[AclGrant] = Field(default_factory=list)
    is_public_policy: bool = False
    encryption: Optional[EncryptionConfig] = None
    versioning_enabled: Optional[bool] = None
    logging_enabled: Optional[bool] = None


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
    """Simulated EC2 security group configuration for security analysis."""
    group_id: str
    group_name: str
    description: str
    inbound_rules: list[InboundRule] = Field(default_factory=list)
    vpc_id: Optional[str] = None


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
    simulated: bool = True


class Warning(BaseModel):
    """A resource that could not be fully scanned."""
    resource_id: str
    reason: str


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


# ---------------------------------------------------------------------------
# API request / response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Request body for POST /api/scan."""
    region: str = "us-east-1"


class ErrorResponse(BaseModel):
    """Standard error response body."""
    code: str
    message: str
