/**
 * TypeScript types mirroring the backend Pydantic models.
 * All types represent SIMULATED data — not real AWS resources.
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
  simulated: boolean
}

export interface Warning {
  resource_id: string
  reason: string
}

export interface ScanResult {
  scan_id: string
  timestamp: string
  simulated: boolean
  region: string
  findings: Finding[]
  warnings: Warning[]
  summary: Record<string, number>
}

// ---------------------------------------------------------------------------
// API models
// ---------------------------------------------------------------------------

export interface ScanRequest {
  region?: string
}

export interface ErrorResponse {
  code: string
  message: string
}
