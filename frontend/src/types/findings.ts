/**
 * TypeScript types mirroring the backend Pydantic models.
 * Session 1: simulated findings. Session 2: adds ScanMode, IdentityInfo,
 * and live scan fields on ScanResult.
 */

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'

export const SEVERITY_ORDER: Severity[] = [
  'Critical',
  'High',
  'Medium',
  'Low',
  'Informational',
]

export const SEVERITY_COLORS: Record<Severity, {
  bg: string
  text: string
  border: string
  dot: string
  card: string
}> = {
  Critical: {
    bg: 'bg-red-900/30',
    text: 'text-red-400',
    border: 'border-red-500/50',
    dot: 'bg-red-500',
    card: 'border-red-500/30 bg-red-950/20',
  },
  High: {
    bg: 'bg-orange-900/30',
    text: 'text-orange-400',
    border: 'border-orange-500/50',
    dot: 'bg-orange-500',
    card: 'border-orange-500/30 bg-orange-950/20',
  },
  Medium: {
    bg: 'bg-yellow-900/30',
    text: 'text-yellow-400',
    border: 'border-yellow-500/50',
    dot: 'bg-yellow-500',
    card: 'border-yellow-500/30 bg-yellow-950/20',
  },
  Low: {
    bg: 'bg-blue-900/30',
    text: 'text-blue-400',
    border: 'border-blue-500/50',
    dot: 'bg-blue-500',
    card: 'border-blue-500/30 bg-blue-950/20',
  },
  Informational: {
    bg: 'bg-slate-800/50',
    text: 'text-slate-400',
    border: 'border-slate-500/50',
    dot: 'bg-slate-500',
    card: 'border-slate-500/30 bg-slate-900/20',
  },
}

// ---------------------------------------------------------------------------
// Scan mode — mirrors backend ScanMode enum
// ---------------------------------------------------------------------------

/** Explicit per-request scan mode. Must match backend ScanMode values exactly. */
export type ScanMode = 'demo' | 'live'

// ---------------------------------------------------------------------------
// S3 resource models
// ---------------------------------------------------------------------------

export interface PublicAccessBlockConfig {
  block_public_acls: boolean
  ignore_public_acls: boolean
  block_public_policy: boolean
  restrict_public_buckets: boolean
}

export interface AclGrant {
  grantee_uri: string
  permission: string
}

export interface EncryptionConfig {
  sse_algorithm: string
  kms_key_id?: string | null
}

export interface S3BucketConfig {
  name: string
  public_access_block: PublicAccessBlockConfig
  acl_grants: AclGrant[]
  is_public_policy: boolean
  encryption: EncryptionConfig | null
  versioning_enabled: boolean | null
  logging_enabled: boolean | null
}

// ---------------------------------------------------------------------------
// EC2 resource models
// ---------------------------------------------------------------------------

export interface InboundRule {
  protocol: string
  from_port: number | null
  to_port: number | null
  cidr_ipv4: string | null
  cidr_ipv6: string | null
  description?: string | null
}

export interface SecurityGroupConfig {
  group_id: string
  group_name: string
  description: string
  inbound_rules: InboundRule[]
  vpc_id?: string | null
}

// ---------------------------------------------------------------------------
// Finding and scan result
// ---------------------------------------------------------------------------

export interface Finding {
  id: string
  resource_type: string
  resource_name: string
  severity: Severity
  title: string
  evidence: Record<string, unknown>
  risk_explanation: string
  remediation: string
  /** true = generated from JSON fixtures; false = generated from real AWS APIs */
  simulated: boolean
}

export interface Warning {
  resource_id: string
  reason: string
}

/** Phase 4D/4E: scan coverage metadata. All fields optional for backward compat. */
export interface ScanCoverage {
  requested_regions: string[]
  scanned_regions: string[]
  failed_regions: string[]
  s3_buckets_requested: number
  s3_buckets_scanned: number
  s3_buckets_failed: number
}

export interface ScanResult {
  scan_id: string
  timestamp: string
  /** Reflects actual data source, not merely the requested mode. */
  simulated: boolean
  region: string
  findings: Finding[]
  warnings: Warning[]
  summary: Record<string, number>
  /** Populated only for live scans. Never contains credentials. */
  aws_account_id: string | null
  aws_identity_arn: string | null
  /** Phase 4D/4E: coverage metadata (optional). */
  coverage?: ScanCoverage | null
}

// ---------------------------------------------------------------------------
// API request / response models
// ---------------------------------------------------------------------------

export interface ScanRequest {
  region?: string
  /** Phase 4E: multiple regions. Overrides 'region' when supplied.
   *  Use ["ALL_ENABLED"] to scan all enabled regions. */
  regions?: string[]
  /** Must be sent explicitly on every request. No implicit default in the client. */
  mode: ScanMode
  /** AWS CLI profile name for live scans. Defaults to the backend's configured profile (AWS_PROFILE env var or 'default'). */
  aws_profile?: string
}

/** AWS caller identity returned by GET /api/identity — no credentials included. */
export interface IdentityInfo {
  account_id: string
  arn: string
  user_id: string
  region: string
  profile: string | null
}

export interface ErrorResponse {
  code: string
  message: string
}

/**
 * AWS CLI profiles discovered on the local machine.
 * Contains profile names only — no credential values, file paths, or secrets.
 */
export interface ProfilesResponse {
  profiles: string[]
  /** AWS_PROFILE env var value if set, otherwise null. */
  default_profile: string | null
  /** Non-null if botocore could not read the AWS configuration files. */
  discovery_error: string | null
}

/** Metadata about a single AWS region for the region selector. */
export interface RegionInfo {
  name: string         // e.g. "eu-north-1"
  description: string  // e.g. "Europe (Stockholm)"
  /**
   * true  = account has opted into this region (or opt-in not required)
   * false = account has NOT opted in
   * null  = availability unknown (DescribeRegions not called or failed)
   */
  enabled: boolean | null
}

/**
 * Region list response from GET /api/regions.
 * regions is always populated from botocore metadata (no AWS call).
 * enabled_regions_available is true only when ec2:DescribeRegions succeeded.
 */
export interface RegionsResponse {
  regions: RegionInfo[]
  enabled_regions_available: boolean
  default_region: string
  describe_regions_error: string | null
}
