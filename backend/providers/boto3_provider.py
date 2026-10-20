"""
Boto3ScannerProvider — Session 2 / Phase 4 implementation of ScannerProvider.

Uses real AWS APIs via the standard Boto3 credential chain.
The AWS CLI profile is supplied per-request (never hardcoded).
No credentials are hardcoded, stored, or logged.

Phase 4A additions:
  list_available_profiles() — discovers configured AWS CLI profiles using
  botocore mechanisms. Returns profile names only; never credential values,
  local file paths, or secrets.

Read-only IAM actions used:
  sts:GetCallerIdentity
  s3:ListAllMyBuckets
  s3:GetBucketPublicAccessBlock
  s3:GetBucketPolicyStatus
  s3:GetBucketAcl
  s3:GetBucketEncryption
  s3:GetBucketVersioning
  s3:GetBucketLogging
  ec2:DescribeSecurityGroups

No write, create, delete, or mutating actions are called.

Security notes:
  - Profile names are validated before use; see _validate_profile_name().
  - External credential helpers (credential_process in ~/.aws/config) are
    listed by profile name but their commands are NOT invoked during
    profile discovery. They are invoked only when boto3 resolves credentials
    for that profile, which is standard boto3 behaviour and trusted local
    configuration, not user-controlled input.
  - The backend is bound to 127.0.0.1. Localhost binding and CORS are not
    authentication mechanisms and do not make these endpoints public-safe.
"""
from __future__ import annotations

import logging
from typing import Any, NamedTuple

import boto3
import botocore.exceptions
import botocore.session

from models import (
    AclGrant,
    EncryptionConfig,
    InboundRule,
    PublicAccessBlockConfig,
    S3BucketConfig,
    SecurityGroupConfig,
    Warning,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Named constants for error classification
# ---------------------------------------------------------------------------

_ACCESS_DENIED_CODES = frozenset({
    "AccessDenied",
    "AccessDeniedException",
    "AuthorizationError",
    "UnauthorizedAccess",
})

_CREDENTIAL_ERROR_CODES = frozenset({
    "ExpiredToken",
    "ExpiredTokenException",
    "TokenRefreshRequired",
    "InvalidClientTokenId",
    "AuthFailure",
    "TokenRetrievalError",  # SSO token cache miss — treat as session expired
})

# ACL grantee URIs that indicate public/authenticated-user access
_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


# ---------------------------------------------------------------------------
# Module-level region discovery
# ---------------------------------------------------------------------------

# Human-readable descriptions for the most common EC2 regions.
# Sourced from AWS documentation; used to improve UX in the region selector.
# Regions not listed here are still returned by botocore — they just show
# the region name without a description.
_REGION_DESCRIPTIONS: dict[str, str] = {
    "us-east-1":      "US East (N. Virginia)",
    "us-east-2":      "US East (Ohio)",
    "us-west-1":      "US West (N. California)",
    "us-west-2":      "US West (Oregon)",
    "af-south-1":     "Africa (Cape Town)",
    "ap-east-1":      "Asia Pacific (Hong Kong)",
    "ap-south-1":     "Asia Pacific (Mumbai)",
    "ap-south-2":     "Asia Pacific (Hyderabad)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)",
    "ap-southeast-4": "Asia Pacific (Melbourne)",
    "ca-central-1":   "Canada (Central)",
    "ca-west-1":      "Canada West (Calgary)",
    "eu-central-1":   "Europe (Frankfurt)",
    "eu-central-2":   "Europe (Zurich)",
    "eu-west-1":      "Europe (Ireland)",
    "eu-west-2":      "Europe (London)",
    "eu-west-3":      "Europe (Paris)",
    "eu-north-1":     "Europe (Stockholm)",
    "eu-south-1":     "Europe (Milan)",
    "eu-south-2":     "Europe (Spain)",
    "il-central-1":   "Israel (Tel Aviv)",
    "me-central-1":   "Middle East (UAE)",
    "me-south-1":     "Middle East (Bahrain)",
    "sa-east-1":      "South America (São Paulo)",
}


def list_known_regions() -> list[str]:
    """Return all EC2 regions known to botocore for this installation.

    Uses botocore's built-in endpoint data — no AWS API call needed.
    These are regions that exist in AWS; they may not all be opted-in
    for a given account (opt-in is checked separately by list_enabled_regions).

    Returns region names as strings, sorted alphabetically.
    Raises RegionDiscoveryError if botocore endpoint data is unavailable.
    """
    try:
        session = botocore.session.Session()
        regions = session.get_available_regions("ec2")
        return sorted(regions)
    except Exception as exc:
        raise RegionDiscoveryError(
            f"Could not read botocore region metadata: {exc}"
        ) from exc


def list_enabled_regions(
    session: "boto3.Session",
    home_region: str = "us-east-1",
) -> tuple[list[str], str | None]:
    """Call ec2:DescribeRegions to get regions enabled for this account.

    Parameters
    ----------
    session:
        An authenticated boto3 Session.
    home_region:
        Region to call DescribeRegions from. The API is global but must be
        called against a specific endpoint. Defaults to us-east-1.

    Returns
    -------
    (enabled_region_names, error_message)
        enabled_region_names: list of region names where the account is enabled.
        error_message: None on success, a safe descriptive string on failure.
        Never returns credential values in the error message.
    """
    try:
        ec2 = session.client("ec2", region_name=home_region)
        # Filters for only opted-in or opt-in-not-required regions
        response = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opted-in", "opt-in-not-required"]}]
        )
        enabled = [r["RegionName"] for r in response.get("Regions", [])]
        return sorted(enabled), None
    except botocore.exceptions.ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in _ACCESS_DENIED_CODES:
            return [], f"ec2:DescribeRegions is not permitted for this profile ({code})."
        if code in _CREDENTIAL_ERROR_CODES:
            return [], f"Credentials expired ({code}). Cannot determine enabled regions."
        return [], f"ec2:DescribeRegions failed ({code})."
    except botocore.exceptions.BotoCoreError as exc:
        return [], f"Could not connect to EC2 to check enabled regions: {type(exc).__name__}"


def _validate_region_name(name: str) -> None:
    """Validate a region name before passing it to boto3.

    AWS region names follow the pattern: {area}-{direction}-{number}
    e.g. us-east-1, eu-north-1, ap-southeast-2

    Rejects names that don't match this pattern to prevent endpoint
    URL manipulation or SSRF via crafted region names.
    boto3 constructs endpoint URLs as https://ec2.{region}.amazonaws.com,
    so a validated region name cannot be used to target non-AWS hosts.

    Raises ValueError with a descriptive message on invalid input.
    """
    import re
    if not name or not name.strip():
        raise ValueError("Region name must not be empty.")
    # Matches standard AWS region naming: two or more groups of lowercase letters/digits
    # separated by hyphens, ending in a digit.  e.g. us-east-1, me-central-1, il-central-1
    if not re.match(r'^[a-z]{2}[a-z0-9-]*-\d+$', name):
        raise ValueError(
            f"Invalid region name format: {name!r}. "
            "Expected format: area-direction-number (e.g. eu-north-1, us-east-1)."
        )
    if len(name) > 30:
        raise ValueError("Region name is too long (maximum 30 characters).")


# ---------------------------------------------------------------------------
# Module-level profile discovery (no session required)
# ---------------------------------------------------------------------------

def list_available_profiles() -> list[str]:
    """Return AWS CLI profile names discovered from local configuration.

    Uses botocore.session.Session().available_profiles — the same discovery
    mechanism used internally by boto3.Session(). This reads ~/.aws/config
    and ~/.aws/credentials.

    Returns profile names only. Never returns credential values, file paths,
    access keys, secret keys, or session tokens.

    External credential helpers (credential_process) are listed by their
    profile name but their commands are NOT executed by this function.
    Credential resolution happens only when boto3 creates a client or calls
    get_credentials() — not during discovery.

    Returns an empty list if no profiles are configured or if botocore
    cannot read the configuration files.

    Raises ProfileDiscoveryError if the configuration is present but
    unreadable (e.g. permission denied on config files).
    """
    try:
        session = botocore.session.Session()
        profiles = session.available_profiles
        # botocore returns a list of strings; make a defensive copy
        return list(profiles)
    except Exception as exc:
        raise ProfileDiscoveryError(
            f"Could not read AWS configuration: {exc}"
        ) from exc


def _validate_profile_name(name: str) -> None:
    """Validate a profile name before passing it to boto3.

    Rejects inputs that could influence filesystem operations:
    - Empty or whitespace-only strings
    - Null bytes (which could truncate filesystem paths)
    - Directory traversal sequences (/ \\ ..)
    - Shell metacharacters used in command injection attacks

    Does NOT enforce a restrictive character allowlist for profile names,
    because botocore supports profile names with spaces, colons, and other
    characters that AWS CLI allows. The goal is to block path/command abuse,
    not to normalise profile naming conventions.

    Raises ValueError with a descriptive message on invalid input.
    """
    if not name or not name.strip():
        raise ValueError("Profile name must not be empty.")

    if len(name) > 512:
        raise ValueError("Profile name is too long (maximum 512 characters).")

    # Reject null bytes — can truncate C-string filesystem paths
    if "\x00" in name:
        raise ValueError("Profile name must not contain null bytes.")

    # Reject directory traversal patterns — normalise separators first
    if ".." in name.replace("\\", "/").split("/"):
        raise ValueError(
            "Profile name must not contain directory traversal sequences (..)."
        )

    # Reject path separators entirely — profile names are keys, not paths
    if "/" in name or "\\" in name:
        raise ValueError(
            "Profile name must not contain path separators (/ or \\)."
        )

    # Reject absolute paths and rooted names
    if name.startswith("/") or name.startswith("\\") or (
        len(name) >= 2 and name[1] == ":"
    ):
        raise ValueError("Profile name must not be an absolute path.")

    # Reject shell command injection characters
    _SHELL_METACHARACTERS = set(";&|`$(){}[]<>!'\"")
    bad = {c for c in name if c in _SHELL_METACHARACTERS}
    if bad:
        raise ValueError(
            f"Profile name contains disallowed characters: "
            f"{', '.join(sorted(bad))}"
        )


# ---------------------------------------------------------------------------
# Exception types for structured error handling
# ---------------------------------------------------------------------------

class ProfileDiscoveryError(Exception):
    """Raised when botocore cannot read the AWS configuration files."""


class RegionDiscoveryError(Exception):
    """Raised when botocore cannot read the region endpoint metadata."""


# ---------------------------------------------------------------------------
# Exception types for credential and permission errors
# ---------------------------------------------------------------------------

class CredentialError(Exception):
    """Raised when AWS credentials are missing, expired, or invalid."""


class SessionExpiredError(CredentialError):
    """AWS SSO/token session has expired. User must run aws sso login."""


class MissingCredentialsError(CredentialError):
    """Profile not found or no credentials configured at all."""


class InvalidProfileError(CredentialError):
    """Profile name is syntactically invalid or contains unsafe characters.

    Raised when _validate_profile_name() rejects the supplied name — before
    any AWS API call is made. Distinct from MissingCredentialsError, which
    means the profile is well-formed but not configured or lacks credentials.
    """


class NetworkError(Exception):
    """Cannot reach the AWS endpoint — connectivity or DNS failure."""


class InsufficientPermissionsError(Exception):
    """Raised when the identity lacks permission for a required list operation."""


# ---------------------------------------------------------------------------
# Internal result type for per-bucket attribute fetches
# ---------------------------------------------------------------------------

class _AttributeResult(NamedTuple):
    """Outcome of a single bucket attribute API call."""
    value: Any          # None if not available
    warning: Warning | None  # populated on any error


# ---------------------------------------------------------------------------
# Provider implementation
# ---------------------------------------------------------------------------

class Boto3ScannerProvider:
    """Calls real AWS APIs to retrieve resource configurations for analysis.

    Instantiated per-request with a specific profile and region, ensuring
    no state is shared between demo and live scan results.

    Parameters
    ----------
    profile_name:
        AWS CLI profile name. Must have active SSO credentials.
        Never hardcoded — always passed from the request or env var.
    region:
        AWS region for EC2 operations. S3 is global but per-bucket
        region APIs are called against the bucket's home region.
    """

    def __init__(self, profile_name: str, region: str = "us-east-1") -> None:
        self._profile_name = profile_name
        self._region = region
        self._session = self._create_session(profile_name)

    # ------------------------------------------------------------------
    # Session factory
    # ------------------------------------------------------------------

    @staticmethod
    def _create_session(profile_name: str) -> boto3.Session:
        """Create a boto3 Session using the named profile.

        Validates the profile name before passing it to boto3 to prevent
        filesystem path abuse. Then raises CredentialError if the profile
        is missing or the session token is expired/invalid.
        Never logs credential values.
        """
        # Validate before passing to boto3 — prevents path traversal, etc.
        try:
            _validate_profile_name(profile_name)
        except ValueError as exc:
            raise InvalidProfileError(
                f"Invalid AWS profile name: {exc}"
            ) from exc

        try:
            session = boto3.Session(profile_name=profile_name)
            # Eagerly validate credentials exist (does NOT call AWS yet)
            creds = session.get_credentials()
            if creds is None:
                raise MissingCredentialsError(
                    f"No credentials found for AWS profile '{profile_name}'. "
                    f"Run 'aws configure --profile {profile_name}' to configure, "
                    f"or 'aws sso login --profile {profile_name}' to authenticate."
                )
            return session
        except botocore.exceptions.ProfileNotFound:
            raise MissingCredentialsError(
                f"AWS profile '{profile_name}' not found in ~/.aws/config. "
                f"Run 'aws configure --profile {profile_name}' to set up, "
                f"or 'aws sso login --profile {profile_name}' if it is an SSO profile."
            )
        except botocore.exceptions.NoCredentialsError:
            raise MissingCredentialsError(
                f"No credentials found for AWS profile '{profile_name}'. "
                f"Run 'aws configure --profile {profile_name}' to configure, "
                f"or 'aws sso login --profile {profile_name}' if this is an SSO profile."
            )

    def get_caller_identity(self) -> dict[str, str]:
        """Call sts:GetCallerIdentity and return account/user metadata.

        Returns a dict with keys: account_id, arn, user_id.
        Raises CredentialError on auth failure.
        Never includes raw credential values in the return or logs.
        """
        try:
            sts = self._session.client("sts", region_name=self._region)
            response = sts.get_caller_identity()
            return {
                "account_id": response["Account"],
                "arn": response["Arn"],
                "user_id": response["UserId"],
            }
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _CREDENTIAL_ERROR_CODES:
                raise SessionExpiredError(
                    f"AWS credentials for profile '{self._profile_name}' are expired "
                    f"or invalid ({code}). Run 'aws sso login --profile "
                    f"{self._profile_name}' if this is an SSO profile."
                ) from exc
            if code in _ACCESS_DENIED_CODES:
                raise InsufficientPermissionsError(
                    f"Profile '{self._profile_name}' does not have sts:GetCallerIdentity "
                    "permission. Add this to the IAM policy."
                ) from exc
            raise CredentialError(
                f"STS identity check failed ({code}): {exc.response['Error']['Message']}"
            ) from exc
        except botocore.exceptions.NoCredentialsError:
            raise MissingCredentialsError(
                f"No valid credentials for profile '{self._profile_name}'. "
                f"Run 'aws configure --profile {self._profile_name}' to configure, "
                f"or 'aws sso login --profile {self._profile_name}' if this is an SSO profile."
            )
        except botocore.exceptions.PartialCredentialsError as exc:
            raise MissingCredentialsError(
                f"Incomplete credentials for profile '{self._profile_name}': {exc}. "
                f"Run 'aws configure --profile {self._profile_name}' to provide all required values."
            ) from exc
        except (
            botocore.exceptions.TokenRetrievalError,
            botocore.exceptions.UnauthorizedSSOTokenError,
            botocore.exceptions.SSOTokenLoadError,
            botocore.exceptions.CredentialRetrievalError,
            botocore.exceptions.RefreshWithMFAUnsupportedError,
        ) as exc:
            raise SessionExpiredError(
                f"AWS credentials for profile '{self._profile_name}' could not be retrieved "
                f"or have expired ({type(exc).__name__}). "
                f"Run 'aws sso login --profile {self._profile_name}' if this is an SSO profile."
            ) from exc
        except botocore.exceptions.BotoCoreError as exc:
            raise NetworkError(f"Could not reach AWS during identity check: {exc}") from exc

    # ------------------------------------------------------------------
    # ScannerProvider interface — S3
    # ------------------------------------------------------------------

    def list_s3_buckets(self) -> list[S3BucketConfig]:
        """Enumerate all S3 buckets and retrieve their security configurations.

        Uses s3:ListAllMyBuckets then per-bucket attribute calls.
        Individual attribute failures are recorded as warnings on the bucket;
        AccessDenied on ListAllMyBuckets raises InsufficientPermissionsError.
        """
        s3 = self._session.client("s3", region_name="us-east-1")

        # List buckets — if this fails it's a scan-level error, not per-resource
        try:
            response = s3.list_buckets()
            buckets_raw = response.get("Buckets", [])
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _CREDENTIAL_ERROR_CODES:
                raise SessionExpiredError(
                    f"Credentials expired ({code}). Run 'aws sso login --profile "
                    f"{self._profile_name}' if this is an SSO profile."
                ) from exc
            raise InsufficientPermissionsError(
                f"s3:ListAllMyBuckets failed ({code}): {exc.response['Error']['Message']}"
            ) from exc

        configs = []
        for bucket_meta in buckets_raw:
            bucket_name = bucket_meta["Name"]
            config = self._build_bucket_config(s3, bucket_name)
            configs.append(config)

        return configs

    def _build_bucket_config(self, s3_client: Any, bucket_name: str) -> S3BucketConfig:
        """Fetch all security-relevant attributes for one S3 bucket.

        Each attribute call is isolated. AccessDenied or missing configuration
        is treated differently:
          - NoSuchPublicAccessBlockConfiguration → no block configured (all False)
          - AccessDenied → attribute cannot be assessed, recorded in evidence
          - Unexpected error → attribute cannot be assessed, recorded in evidence
        """
        # Public access block
        pab_result = self._get_public_access_block(s3_client, bucket_name)
        public_access_block = pab_result.value or PublicAccessBlockConfig(
            block_public_acls=False,
            ignore_public_acls=False,
            block_public_policy=False,
            restrict_public_buckets=False,
        )

        # Bucket ACL
        acl_result = self._get_bucket_acl(s3_client, bucket_name)
        acl_grants = acl_result.value if acl_result.value is not None else []

        # Policy public status
        policy_result = self._get_bucket_policy_status(s3_client, bucket_name)
        is_public_policy = policy_result.value if policy_result.value is not None else False

        # Encryption
        enc_result = self._get_bucket_encryption(s3_client, bucket_name)
        encryption = enc_result.value  # None if not configured or error

        # Versioning
        ver_result = self._get_bucket_versioning(s3_client, bucket_name)
        versioning_enabled = ver_result.value  # None if error, bool if fetched

        # Logging
        log_result = self._get_bucket_logging(s3_client, bucket_name)
        logging_enabled = log_result.value  # None if error, bool if fetched

        return S3BucketConfig(
            name=bucket_name,
            public_access_block=public_access_block,
            acl_grants=acl_grants,
            is_public_policy=is_public_policy,
            encryption=encryption,
            versioning_enabled=versioning_enabled,
            logging_enabled=logging_enabled,
        )

    # ------------------------------------------------------------------
    # S3 per-attribute fetchers
    # ------------------------------------------------------------------

    def _get_public_access_block(self, s3: Any, bucket: str) -> _AttributeResult:
        try:
            resp = s3.get_bucket_public_access_block(Bucket=bucket)
            cfg = resp["PublicAccessBlockConfiguration"]
            return _AttributeResult(
                value=PublicAccessBlockConfig(
                    block_public_acls=cfg.get("BlockPublicAcls", False),
                    ignore_public_acls=cfg.get("IgnorePublicAcls", False),
                    block_public_policy=cfg.get("BlockPublicPolicy", False),
                    restrict_public_buckets=cfg.get("RestrictPublicBuckets", False),
                ),
                warning=None,
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                # Bucket has no block config — this is meaningful (all settings absent)
                return _AttributeResult(
                    value=PublicAccessBlockConfig(
                        block_public_acls=False,
                        ignore_public_acls=False,
                        block_public_policy=False,
                        restrict_public_buckets=False,
                    ),
                    warning=None,
                )
            if code in _ACCESS_DENIED_CODES:
                return _AttributeResult(
                    value=None,
                    warning=Warning(
                        resource_id=f"s3:{bucket}:public_access_block",
                        reason=f"AccessDenied — s3:GetBucketPublicAccessBlock on '{bucket}'",
                    ),
                )
            return _AttributeResult(
                value=None,
                warning=Warning(
                    resource_id=f"s3:{bucket}:public_access_block",
                    reason=f"API error ({code}) fetching public access block for '{bucket}'",
                ),
            )

    def _get_bucket_acl(self, s3: Any, bucket: str) -> _AttributeResult:
        try:
            resp = s3.get_bucket_acl(Bucket=bucket)
            grants = []
            for grant in resp.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                perm = grant.get("Permission", "")
                if uri:
                    grants.append(AclGrant(grantee_uri=uri, permission=perm))
            return _AttributeResult(value=grants, warning=None)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _ACCESS_DENIED_CODES:
                return _AttributeResult(
                    value=None,
                    warning=Warning(
                        resource_id=f"s3:{bucket}:acl",
                        reason=f"AccessDenied — s3:GetBucketAcl on '{bucket}'",
                    ),
                )
            return _AttributeResult(
                value=None,
                warning=Warning(
                    resource_id=f"s3:{bucket}:acl",
                    reason=f"API error ({code}) fetching ACL for '{bucket}'",
                ),
            )

    def _get_bucket_policy_status(self, s3: Any, bucket: str) -> _AttributeResult:
        try:
            resp = s3.get_bucket_policy_status(Bucket=bucket)
            is_public = resp["PolicyStatus"].get("IsPublic", False)
            return _AttributeResult(value=is_public, warning=None)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucketPolicy":
                # No bucket policy — not public
                return _AttributeResult(value=False, warning=None)
            if code in _ACCESS_DENIED_CODES:
                return _AttributeResult(
                    value=None,
                    warning=Warning(
                        resource_id=f"s3:{bucket}:policy_status",
                        reason=f"AccessDenied — s3:GetBucketPolicyStatus on '{bucket}'",
                    ),
                )
            return _AttributeResult(
                value=None,
                warning=Warning(
                    resource_id=f"s3:{bucket}:policy_status",
                    reason=f"API error ({code}) fetching policy status for '{bucket}'",
                ),
            )

    def _get_bucket_encryption(self, s3: Any, bucket: str) -> _AttributeResult:
        try:
            resp = s3.get_bucket_encryption(Bucket=bucket)
            rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                return _AttributeResult(value=None, warning=None)
            rule = rules[0]
            sse = rule.get("ApplyServerSideEncryptionByDefault", {})
            algorithm = sse.get("SSEAlgorithm", "AES256")
            kms_key = sse.get("KMSMasterKeyID")
            return _AttributeResult(
                value=EncryptionConfig(sse_algorithm=algorithm, kms_key_id=kms_key),
                warning=None,
            )
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ServerSideEncryptionConfigurationNotFoundError",
                        "NoSuchEncryptionConfiguration"):
                # No default encryption — not an error, just not configured
                return _AttributeResult(value=None, warning=None)
            if code in _ACCESS_DENIED_CODES:
                return _AttributeResult(
                    value=None,
                    warning=Warning(
                        resource_id=f"s3:{bucket}:encryption",
                        reason=f"AccessDenied — s3:GetBucketEncryption on '{bucket}'",
                    ),
                )
            return _AttributeResult(
                value=None,
                warning=Warning(
                    resource_id=f"s3:{bucket}:encryption",
                    reason=f"API error ({code}) fetching encryption config for '{bucket}'",
                ),
            )

    def _get_bucket_versioning(self, s3: Any, bucket: str) -> _AttributeResult:
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket)
            status = resp.get("Status", "")
            return _AttributeResult(value=(status == "Enabled"), warning=None)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _ACCESS_DENIED_CODES:
                return _AttributeResult(
                    value=None,
                    warning=Warning(
                        resource_id=f"s3:{bucket}:versioning",
                        reason=f"AccessDenied — s3:GetBucketVersioning on '{bucket}'",
                    ),
                )
            return _AttributeResult(
                value=None,
                warning=Warning(
                    resource_id=f"s3:{bucket}:versioning",
                    reason=f"API error ({code}) fetching versioning for '{bucket}'",
                ),
            )

    def _get_bucket_logging(self, s3: Any, bucket: str) -> _AttributeResult:
        try:
            resp = s3.get_bucket_logging(Bucket=bucket)
            logging_enabled = "LoggingEnabled" in resp
            return _AttributeResult(value=logging_enabled, warning=None)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _ACCESS_DENIED_CODES:
                return _AttributeResult(
                    value=None,
                    warning=Warning(
                        resource_id=f"s3:{bucket}:logging",
                        reason=f"AccessDenied — s3:GetBucketLogging on '{bucket}'",
                    ),
                )
            return _AttributeResult(
                value=None,
                warning=Warning(
                    resource_id=f"s3:{bucket}:logging",
                    reason=f"API error ({code}) fetching logging config for '{bucket}'",
                ),
            )

    # ------------------------------------------------------------------
    # ScannerProvider interface — EC2
    # ------------------------------------------------------------------

    def list_security_groups(self, region: str) -> list[SecurityGroupConfig]:
        """Enumerate all EC2 security groups in the specified region.

        Uses ec2:DescribeSecurityGroups with pagination.
        AccessDenied raises InsufficientPermissionsError.
        """
        ec2 = self._session.client("ec2", region_name=region)
        groups = []
        paginator = ec2.get_paginator("describe_security_groups")

        try:
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    inbound_rules = self._parse_inbound_rules(sg.get("IpPermissions", []))
                    groups.append(SecurityGroupConfig(
                        group_id=sg["GroupId"],
                        group_name=sg.get("GroupName", sg["GroupId"]),
                        description=sg.get("Description", ""),
                        inbound_rules=inbound_rules,
                        vpc_id=sg.get("VpcId"),
                    ))
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _CREDENTIAL_ERROR_CODES:
                raise SessionExpiredError(
                    f"Credentials expired ({code}). Run 'aws sso login --profile "
                    f"{self._profile_name}' if this is an SSO profile."
                ) from exc
            raise InsufficientPermissionsError(
                f"ec2:DescribeSecurityGroups failed in '{region}' ({code}): "
                f"{exc.response['Error']['Message']}"
            ) from exc

        return groups

    @staticmethod
    def _parse_inbound_rules(ip_permissions: list[dict]) -> list[InboundRule]:
        """Convert EC2 IpPermissions to InboundRule models.

        Each IP range (IPv4 or IPv6) in a permission entry becomes a separate
        InboundRule so that the existing ec2_rules.py classify_rule() logic
        works unchanged (it operates on one CIDR per rule).
        """
        rules = []
        for perm in ip_permissions:
            protocol = perm.get("IpProtocol", "-1")
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")

            # IPv4 ranges
            for ip_range in perm.get("IpRanges", []):
                rules.append(InboundRule(
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    cidr_ipv4=ip_range.get("CidrIp"),
                    cidr_ipv6=None,
                    description=ip_range.get("Description"),
                ))

            # IPv6 ranges
            for ipv6_range in perm.get("Ipv6Ranges", []):
                rules.append(InboundRule(
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    cidr_ipv4=None,
                    cidr_ipv6=ipv6_range.get("CidrIpv6"),
                    description=ipv6_range.get("Description"),
                ))

            # If no ranges at all, add one rule entry with no CIDR
            # (non-world-open, so classify_rule returns None — correct)
            if not perm.get("IpRanges") and not perm.get("Ipv6Ranges"):
                rules.append(InboundRule(
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    cidr_ipv4=None,
                    cidr_ipv6=None,
                    description=None,
                ))

        return rules
