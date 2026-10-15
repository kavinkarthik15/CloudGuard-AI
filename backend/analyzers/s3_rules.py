"""
S3 bucket security misconfiguration detection rules.

Each rule is a pure function accepting S3BucketConfig and returning
Finding | None. The Analyzer calls them in sequence for every bucket.

All findings include simulated=True and explicitly state this finding
is based on simulated configuration data.
"""
from __future__ import annotations

from models import (
    AclGrant,
    EncryptionConfig,
    Finding,
    S3BucketConfig,
    Severity,
)

# ACL grantee URIs that indicate public access
_PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
_PUBLIC_PERMISSIONS = {"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}


def _has_public_acl(acl_grants: list[AclGrant]) -> bool:
    """Return True if any ACL grant gives public access."""
    for grant in acl_grants:
        if (
            grant.grantee_uri in _PUBLIC_GRANTEE_URIS
            and grant.permission in _PUBLIC_PERMISSIONS
        ):
            return True
    return False


def _is_effectively_public(bucket: S3BucketConfig) -> bool:
    """Return True if the bucket meets the full effective-public threshold:
    at least one block setting disabled AND (ACL public OR policy public).
    """
    if not bucket.public_access_block.any_disabled:
        return False
    return _has_public_acl(bucket.acl_grants) or bucket.is_public_policy


# ---------------------------------------------------------------------------
# Rule functions
# ---------------------------------------------------------------------------

def check_effective_public_acl_or_policy(bucket: S3BucketConfig) -> Finding | None:
    """Critical: effectively public bucket (block disabled AND ACL/policy public)."""
    if not _is_effectively_public(bucket):
        return None

    disabled = bucket.public_access_block.disabled_settings()
    public_acl_grants = [
        {"grantee_uri": g.grantee_uri, "permission": g.permission}
        for g in bucket.acl_grants
        if g.grantee_uri in _PUBLIC_GRANTEE_URIS
    ]
    contributing_factors = []
    if public_acl_grants:
        contributing_factors.append("ACL grants public access")
    if bucket.is_public_policy:
        contributing_factors.append("bucket policy allows public access")

    return Finding(
        resource_type="S3Bucket",
        resource_name=bucket.name,
        severity=Severity.Critical,
        title=f"S3 Bucket '{bucket.name}' is effectively publicly accessible",
        evidence={
            "disabled_block_settings": disabled,
            "public_acl_grants": public_acl_grants,
            "is_public_policy": bucket.is_public_policy,
            "contributing_factors": contributing_factors,
        },
        risk_explanation=(
            f"This finding is based on simulated configuration data. "
            f"The bucket '{bucket.name}' has all four S3 Block Public Access "
            f"settings partially or fully disabled, AND {' and '.join(contributing_factors)}. "
            "This combination makes the bucket contents accessible to the public internet, "
            "potentially exposing sensitive data. Configuration risk — not confirmed exploitation."
        ),
        remediation=(
            "1. Enable all four S3 Block Public Access settings: "
            "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets. "
            "2. Remove any ACL grants to AllUsers or AuthenticatedUsers. "
            "3. Review and restrict the bucket policy to deny public access. "
            "4. Use IAM policies to grant access only to authorized principals."
        ),
    )


def check_partial_public_access_block(bucket: S3BucketConfig) -> Finding | None:
    """High: some but not all block settings disabled, not already Critical."""
    if not bucket.public_access_block.any_disabled:
        return None
    # Skip if already a Critical finding (both conditions met)
    if _is_effectively_public(bucket):
        return None

    disabled = bucket.public_access_block.disabled_settings()

    return Finding(
        resource_type="S3Bucket",
        resource_name=bucket.name,
        severity=Severity.High,
        title=f"S3 Bucket '{bucket.name}' has incomplete public access block configuration",
        evidence={
            "disabled_block_settings": disabled,
            "all_four_settings_required": [
                "block_public_acls",
                "ignore_public_acls",
                "block_public_policy",
                "restrict_public_buckets",
            ],
        },
        risk_explanation=(
            f"This finding is based on simulated configuration data. "
            f"The bucket '{bucket.name}' has {len(disabled)} of 4 S3 Block Public Access "
            f"settings disabled: {', '.join(disabled)}. "
            "While the bucket is not currently effectively public, partial configuration "
            "creates risk of accidental public exposure if ACL or policy settings change. "
            "Configuration risk — not confirmed exploitation."
        ),
        remediation=(
            "Enable all four S3 Block Public Access settings on this bucket: "
            "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets. "
            "This provides defense-in-depth against accidental public exposure regardless "
            "of bucket policy or ACL configuration."
        ),
    )


def check_no_encryption(bucket: S3BucketConfig) -> Finding | None:
    """High: no default server-side encryption configured."""
    if bucket.encryption is not None:
        return None

    return Finding(
        resource_type="S3Bucket",
        resource_name=bucket.name,
        severity=Severity.High,
        title=f"S3 Bucket '{bucket.name}' has no default encryption configured",
        evidence={"encryption": None},
        risk_explanation=(
            f"This finding is based on simulated configuration data. "
            f"The bucket '{bucket.name}' does not have a default server-side "
            "encryption (SSE) rule configured. Objects stored without an explicit "
            "encryption header will be stored unencrypted, risking data exposure "
            "if access controls are misconfigured or storage media is compromised. "
            "Configuration risk — not confirmed exploitation."
        ),
        remediation=(
            "Enable default server-side encryption on this bucket. "
            "Recommended options: "
            "1. SSE-S3 (AES-256): Simple, no additional cost. "
            "2. SSE-KMS: Uses AWS KMS customer-managed keys for audit trail and access control. "
            "Apply via: S3 console → Bucket → Properties → Default encryption → Enable."
        ),
    )


def check_sse_s3_only(bucket: S3BucketConfig) -> Finding | None:
    """Informational: encryption is SSE-S3 (AES256) rather than SSE-KMS."""
    if bucket.encryption is None:
        return None
    if bucket.encryption.sse_algorithm != "AES256":
        return None

    return Finding(
        resource_type="S3Bucket",
        resource_name=bucket.name,
        severity=Severity.Informational,
        title=f"S3 Bucket '{bucket.name}' uses SSE-S3 encryption (KMS recommended)",
        evidence={"sse_algorithm": "AES256", "kms_key_id": None},
        risk_explanation=(
            f"This finding is based on simulated configuration data. "
            f"The bucket '{bucket.name}' uses SSE-S3 (AES-256) encryption, which provides "
            "data-at-rest protection. However, SSE-KMS with customer-managed keys provides "
            "stronger controls including key rotation audit trails, access control via IAM, "
            "and the ability to revoke access by disabling the key. "
            "Informational — not a vulnerability."
        ),
        remediation=(
            "Consider upgrading to SSE-KMS encryption with a customer-managed KMS key "
            "if your security policy requires key management controls or audit trails. "
            "Steps: S3 console → Bucket → Properties → Default encryption → "
            "Server-side encryption with AWS Key Management Service keys (SSE-KMS) → "
            "Select or create a KMS key."
        ),
    )


def check_versioning_disabled(bucket: S3BucketConfig) -> Finding | None:
    """Low (optional): versioning is not enabled."""
    if bucket.versioning_enabled is None:
        return None
    if bucket.versioning_enabled:
        return None

    return Finding(
        resource_type="S3Bucket",
        resource_name=bucket.name,
        severity=Severity.Low,
        title=f"S3 Bucket '{bucket.name}' does not have versioning enabled",
        evidence={"versioning_enabled": False},
        risk_explanation=(
            f"This finding is based on simulated configuration data. "
            f"The bucket '{bucket.name}' does not have versioning enabled. "
            "Without versioning, accidentally deleted or overwritten objects cannot be recovered. "
            "This increases risk of data loss from human error or ransomware attacks. "
            "Low severity — configuration best practice."
        ),
        remediation=(
            "Enable S3 bucket versioning: "
            "S3 console → Bucket → Properties → Bucket Versioning → Enable. "
            "Consider enabling MFA Delete for additional protection against accidental deletion. "
            "Set up a lifecycle policy to expire old versions and manage storage costs."
        ),
    )


def check_authenticated_users_acl(bucket: S3BucketConfig) -> Finding | None:
    """Medium: ACL grants AuthenticatedUsers access even though block settings are ON.
    Block Public Access prevents anonymous access, but any authenticated AWS account
    can still access the bucket — this is rarely intentional.
    """
    if not bucket.public_access_block.all_enabled:
        # Already covered by Critical or High rules above
        return None

    for grant in bucket.acl_grants:
        if (
            grant.grantee_uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            and grant.permission in _PUBLIC_PERMISSIONS
        ):
            return Finding(
                resource_type="S3Bucket",
                resource_name=bucket.name,
                severity=Severity.Medium,
                title=f"S3 Bucket '{bucket.name}' grants access to all authenticated AWS users via ACL",
                evidence={
                    "acl_grant": {"grantee_uri": grant.grantee_uri, "permission": grant.permission},
                    "block_public_access": "all_enabled",
                    "note": "Block Public Access is enabled but AuthenticatedUsers ACL bypasses it for authenticated AWS accounts",
                },
                risk_explanation=(
                    f"This finding is based on simulated configuration data. "
                    f"The bucket '{bucket.name}' grants {grant.permission} access to the "
                    "'AuthenticatedUsers' group, which includes any authenticated AWS account "
                    "globally — not just accounts in your organization. While S3 Block Public "
                    "Access prevents anonymous access, this ACL allows any of the millions of "
                    "AWS accounts worldwide to access objects in this bucket. "
                    "Medium severity — configuration risk, not confirmed exploitation."
                ),
                remediation=(
                    f"Remove the AuthenticatedUsers ACL grant from bucket '{bucket.name}': "
                    "1. S3 console → Bucket → Permissions → Access Control List → Edit. "
                    "2. Remove the 'Authenticated Users group' entry. "
                    "3. Replace with explicit IAM policies granting access only to specific "
                    "principals (users, roles, or accounts) that require it. "
                    "4. Use bucket policies with aws:PrincipalOrgID condition to restrict to your AWS Organization."
                ),
            )
    return None


def check_logging_disabled(bucket: S3BucketConfig) -> Finding | None:
    """Informational (optional): access logging is not enabled."""
    if bucket.logging_enabled is None:
        return None
    if bucket.logging_enabled:
        return None

    return Finding(
        resource_type="S3Bucket",
        resource_name=bucket.name,
        severity=Severity.Informational,
        title=f"S3 Bucket '{bucket.name}' does not have server access logging enabled",
        evidence={"logging_enabled": False},
        risk_explanation=(
            f"This finding is based on simulated configuration data. "
            f"The bucket '{bucket.name}' does not have server access logging enabled. "
            "Without access logs, it is difficult to audit who accessed or modified objects, "
            "which limits incident investigation capability. "
            "Informational — not a direct security vulnerability."
        ),
        remediation=(
            "Enable S3 server access logging: "
            "S3 console → Bucket → Properties → Server access logging → Enable. "
            "Specify a target bucket to receive the log files. "
            "Consider using AWS CloudTrail for data plane events for more comprehensive auditing."
        ),
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_s3_bucket(bucket: S3BucketConfig) -> list[Finding]:
    """Run all S3 security rules against a bucket configuration.

    Returns a list of all Findings (may be empty for a clean bucket).
    Rules are independent — a bucket can trigger multiple findings.
    """
    rules = [
        check_effective_public_acl_or_policy,
        check_partial_public_access_block,
        check_no_encryption,
        check_sse_s3_only,
        check_authenticated_users_acl,
        check_versioning_disabled,
        check_logging_disabled,
    ]
    findings = []
    for rule in rules:
        result = rule(bucket)
        if result is not None:
            findings.append(result)
    return findings
