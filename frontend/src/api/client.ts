/**
 * API client for CloudGuard AI backend.
 *
 * All endpoints use simulated data in Session 1.
 * No real AWS credentials or API calls are made.
 */
import type { ErrorResponse, ScanRequest, ScanResult } from '../types/findings'

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
  async health(): Promise<{ status: string; simulated: boolean }> {
    const response = await fetchWithTimeout(`${BASE_URL}/api/health`)
    return parseJson(response)
  },

  async triggerScan(request: ScanRequest = {}): Promise<ScanResult> {
    const response = await fetchWithTimeout(`${BASE_URL}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ region: request.region ?? 'us-east-1' }),
    })
    return parseJson<ScanResult>(response)
  },

  async exportJson(): Promise<Blob> {
    const response = await fetchWithTimeout(`${BASE_URL}/api/export/json`)
    if (!response.ok) {
      const body = await response.json().catch(() => ({})) as Partial<ErrorResponse>
      throw new ApiError(
        body.code ?? 'EXPORT_ERROR',
        body.message ?? 'Failed to generate JSON export',
      )
    }
    return response.blob()
  },

  async exportCsv(): Promise<Blob> {
    const response = await fetchWithTimeout(`${BASE_URL}/api/export/csv`)
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
