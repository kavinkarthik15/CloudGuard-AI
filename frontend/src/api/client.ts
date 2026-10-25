/**
 * API client for CloudGuard AI backend.
 *
 * Session 1: demo mode only (simulated findings).
 * Session 2: adds live AWS mode via checkIdentity() and explicit mode on triggerScan().
 *
 * Export correctness:
 *   exportJson(scanId) and exportCsv(scanId) use the scan-id-specific backend
 *   endpoints (/api/export/{scan_id}/json), ensuring the downloaded file always
 *   corresponds to the scan that produced the currently displayed findings.
 *   A missing or expired scan_id returns SCAN_NOT_FOUND (404), not stale data.
 *
 * Security: never sends or receives AWS credentials, access keys, or session tokens.
 */
import type { ErrorResponse, IdentityInfo, ProfilesResponse, RegionsResponse, ScanRequest, ScanResult } from '../types/findings'

const BASE_URL = (import.meta.env.VITE_API_BASE_URL as string) || 'http://127.0.0.1:8001'

// ---------------------------------------------------------------------------
// Typed error class
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

// ---------------------------------------------------------------------------
// Fetch with AbortController timeout
// ---------------------------------------------------------------------------

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 120_000,
): Promise<Response> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, { ...options, signal: controller.signal })
    return response
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiError('REQUEST_TIMEOUT', 'Request timed out — please try again')
    }
    throw new ApiError(
      'NETWORK_ERROR',
      'Could not connect to the CloudGuard AI backend. Is it running?',
    )
  } finally {
    clearTimeout(timeoutId)
  }
}

// ---------------------------------------------------------------------------
// Response parsing helpers
// ---------------------------------------------------------------------------

async function parseJson<T>(response: Response): Promise<T> {
  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new ApiError('PARSE_ERROR', `Unexpected response from server (HTTP ${response.status})`)
  }

  if (!response.ok) {
    const err = body as Partial<ErrorResponse>
    throw new ApiError(
      err.code ?? 'UNKNOWN_ERROR',
      err.message ?? `Request failed with status ${response.status}`,
    )
  }

  return body as T
}

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

export const scanApi = {
  async health(): Promise<{ status: string; live_mode_available: boolean }> {
    const response = await fetchWithTimeout(`${BASE_URL}/api/health`)
    return parseJson(response)
  },

  /**
   * Discover AWS CLI profiles configured on the local machine.
   * Returns profile names only — no credentials, file paths, or secrets.
   * The discovery_error field is set if botocore cannot read config files.
   * This endpoint never invokes external credential helpers.
   */
  async listProfiles(): Promise<ProfilesResponse> {
    const response = await fetchWithTimeout(`${BASE_URL}/api/profiles`, {}, 10_000)
    return parseJson<ProfilesResponse>(response)
  },

  /**
   * Fetch the list of AWS EC2 regions from botocore metadata.
   * Optionally enriched with ec2:DescribeRegions for the given profile.
   * Never makes mutating AWS API calls.
   */
  async listRegions(profile?: string): Promise<RegionsResponse> {
    const params = new URLSearchParams()
    if (profile) params.set('profile', profile)
    const qs = params.toString() ? `?${params.toString()}` : ''
    const response = await fetchWithTimeout(
      `${BASE_URL}/api/regions${qs}`, {}, 30_000,
    )
    return parseJson<RegionsResponse>(response)
  },

  /**
   * Verify AWS credentials before initiating a live scan.
   * Returns caller identity metadata — no credentials included.
   * Throws ApiError with code INVALID_CREDENTIALS (401) or
   * INSUFFICIENT_PERMISSIONS (403) on failure.
   */
  async checkIdentity(profile?: string, region?: string): Promise<IdentityInfo> {
    const params = new URLSearchParams()
    if (profile) params.set('profile', profile)
    if (region) params.set('region', region)
    const qs = params.toString() ? `?${params.toString()}` : ''
    const response = await fetchWithTimeout(
      `${BASE_URL}/api/identity${qs}`,
      {},
      30_000,
    )
    return parseJson<IdentityInfo>(response)
  },

  /**
   * Trigger a scan. Mode must be explicitly supplied on every call.
   * The returned ScanResult.scan_id must be passed to exportJson() / exportCsv()
   * to guarantee the export matches the displayed findings.
   */
  async triggerScan(request: ScanRequest): Promise<ScanResult> {
    const body: Record<string, unknown> = {
      region: request.region ?? 'us-east-1',
      mode: request.mode,
    }
    // Phase 4E: pass regions array when present
    if (request.regions && request.regions.length > 0) {
      body.regions = request.regions
    }
    if (request.mode === 'live' && request.aws_profile) {
      body.aws_profile = request.aws_profile
    }
    const response = await fetchWithTimeout(`${BASE_URL}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    return parseJson<ScanResult>(response)
  },

  /**
   * Download JSON export for a specific scan.
   * The scan_id must come from a ScanResult previously returned by triggerScan().
   * Throws ApiError with code SCAN_NOT_FOUND if the scan has expired or the
   * server restarted since the scan ran.
   */
  async exportJson(scanId: string): Promise<Blob> {
    const response = await fetchWithTimeout(
      `${BASE_URL}/api/export/${encodeURIComponent(scanId)}/json`,
    )
    if (!response.ok) {
      const body = await response.json().catch(() => ({})) as Partial<ErrorResponse>
      throw new ApiError(
        body.code ?? 'EXPORT_ERROR',
        body.message ?? 'Failed to generate JSON export',
      )
    }
    return response.blob()
  },

  /**
   * Download CSV export for a specific scan.
   * Same scan_id requirements as exportJson().
   */
  async exportCsv(scanId: string): Promise<Blob> {
    const response = await fetchWithTimeout(
      `${BASE_URL}/api/export/${encodeURIComponent(scanId)}/csv`,
    )
    if (!response.ok) {
      const body = await response.json().catch(() => ({})) as Partial<ErrorResponse>
      throw new ApiError(
        body.code ?? 'EXPORT_ERROR',
        body.message ?? 'Failed to generate CSV export',
      )
    }
    return response.blob()
  },
}
