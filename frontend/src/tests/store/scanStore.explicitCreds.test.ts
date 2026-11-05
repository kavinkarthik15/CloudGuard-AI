/**
 * Tests for explicit credential authentication in the scan store.
 *
 * Verifies:
 * - checkIdentity forwards credentials to scanApi without storing them
 * - triggerScan forwards credentials to scanApi without storing them
 * - Demo scans never receive credentials
 * - Credentials never appear in Zustand state
 * - Existing live scan persistence behavior remains intact
 *
 * All AWS calls are mocked — no real credentials used.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act } from 'react'
import { useScanStore } from '../../store/scanStore'
import type { IdentityInfo, ScanResult } from '../../types/findings'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const FAKE_CREDS = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  sessionToken: undefined,
} as const

const FAKE_CREDS_WITH_TOKEN = {
  accessKeyId: 'ASIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  sessionToken: 'FwoGZXIvYXdzEJr//////////EXAMPLE',
} as const

function mockIdentityInfo(overrides: Partial<IdentityInfo> = {}): IdentityInfo {
  return {
    account_id: '316658062107',
    arn: 'arn:aws:sts::316658062107:assumed-role/CloudGuardRole/session',
    user_id: 'AROAEXAMPLE:session',
    region: 'eu-north-1',
    profile: null, // null for explicit creds
    ...overrides,
  }
}

function mockLiveScanResult(): ScanResult {
  return {
    scan_id: 'live-001',
    timestamp: new Date().toISOString(),
    simulated: false,
    region: 'eu-north-1',
    findings: [],
    warnings: [],
    summary: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
    aws_account_id: '316658062107',
    aws_identity_arn: 'arn:aws:sts::316658062107:assumed-role/Role/s',
    coverage: {
      requested_regions: ['eu-north-1'],
      scanned_regions: ['eu-north-1'],
      failed_regions: [],
      s3_buckets_requested: 0,
      s3_buckets_scanned: 0,
      s3_buckets_failed: 0,
      ec2_sgs_discovered: 1,
      ec2_sgs_evaluated: 1,
      ec2_sgs_failed: 0,
    },
  }
}

beforeEach(() => {
  act(() => {
    useScanStore.setState({
      status: 'idle',
      scanResult: null,
      error: null,
      lastScanAt: null,
      selectedMode: 'live',
      profiles: [],
      profilesLoading: false,
      profilesError: null,
      regionList: [],
      regionsLoading: false,
      regionsError: null,
      enabledRegionsAvailable: false,
      identityStatus: 'idle',
      identityInfo: null,
      identityError: null,
      identityErrorCode: null,
      verifiedFor: null,
      awsProfile: 'default',
      awsRegion: 'eu-north-1',
      regionMode: 'single',
      selectedRegions: ['eu-north-1'],
    })
  })
})

// ---------------------------------------------------------------------------
// checkIdentity with explicit credentials
// ---------------------------------------------------------------------------

describe('checkIdentity with explicit credentials', () => {
  it('forwards explicit creds to scanApi.checkIdentity', async () => {
    const { scanApi } = await import('../../api/client')
    const spy = vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentityInfo())

    await act(async () => {
      await useScanStore.getState().checkIdentity(FAKE_CREDS)
    })

    expect(spy).toHaveBeenCalledWith('default', 'eu-north-1', FAKE_CREDS)
  })

  it('forwards session token when provided', async () => {
    const { scanApi } = await import('../../api/client')
    const spy = vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentityInfo())

    await act(async () => {
      await useScanStore.getState().checkIdentity(FAKE_CREDS_WITH_TOKEN)
    })

    expect(spy).toHaveBeenCalledWith('default', 'eu-north-1', FAKE_CREDS_WITH_TOKEN)
    const calledCreds = spy.mock.calls[0][2]
    expect(calledCreds?.sessionToken).toBe(FAKE_CREDS_WITH_TOKEN.sessionToken)
  })

  it('credential values are never stored in Zustand state', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentityInfo())

    await act(async () => {
      await useScanStore.getState().checkIdentity(FAKE_CREDS)
    })

    const state = useScanStore.getState() as unknown as Record<string, unknown>
    const stateJson = JSON.stringify(state)
    expect(stateJson).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(stateJson).not.toContain('wJalrXUtnFEMI')
  })

  it('sets identityStatus=verified on success', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentityInfo())

    await act(async () => {
      await useScanStore.getState().checkIdentity(FAKE_CREDS)
    })

    expect(useScanStore.getState().identityStatus).toBe('verified')
    expect(useScanStore.getState().identityInfo?.account_id).toBe('316658062107')
  })

  it('sets identityStatus=error on auth failure', async () => {
    const { ApiError, scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockRejectedValueOnce(
      new ApiError('NO_CREDENTIALS', 'Invalid credentials')
    )

    await act(async () => {
      await useScanStore.getState().checkIdentity(FAKE_CREDS)
    })

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('error')
    expect(state.identityErrorCode).toBe('NO_CREDENTIALS')
    // Error message must not contain credential values
    expect(state.identityError).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(state.identityError).not.toContain('wJalrXUtnFEMI')
  })

  it('without explicit creds, calls scanApi.checkIdentity without third arg', async () => {
    const { scanApi } = await import('../../api/client')
    const spy = vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentityInfo())

    await act(async () => {
      await useScanStore.getState().checkIdentity()
    })

    expect(spy).toHaveBeenCalledWith('default', 'eu-north-1', undefined)
  })
})

// ---------------------------------------------------------------------------
// triggerScan with explicit credentials
// ---------------------------------------------------------------------------

describe('triggerScan with explicit credentials', () => {
  it('includes explicit creds in scan request when provided', async () => {
    const { scanApi } = await import('../../api/client')
    const spy = vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockLiveScanResult())

    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        verifiedFor: { profile: 'default', region: 'eu-north-1', verificationGen: 1 },
        awsProfile: 'default',
        awsRegion: 'eu-north-1',
        identityStatus: 'verified',
      })
    })

    await act(async () => {
      await useScanStore.getState().triggerScan(undefined, FAKE_CREDS)
    })

    const callArg = spy.mock.calls[0][0]
    expect(callArg.aws_access_key_id).toBe(FAKE_CREDS.accessKeyId)
    // secret should be present but we don't assert its value to avoid test failure echo
    expect(callArg.aws_secret_access_key).toBeDefined()
    // must NOT include aws_profile when using explicit creds
    expect(callArg.aws_profile).toBeUndefined()
  })

  it('credential values are not stored in Zustand state after scan', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockLiveScanResult())

    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        verifiedFor: { profile: 'default', region: 'eu-north-1', verificationGen: 1 },
        awsProfile: 'default',
        awsRegion: 'eu-north-1',
        identityStatus: 'verified',
      })
    })

    await act(async () => {
      await useScanStore.getState().triggerScan(undefined, FAKE_CREDS)
    })

    const stateJson = JSON.stringify(useScanStore.getState())
    expect(stateJson).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(stateJson).not.toContain('wJalrXUtnFEMI')
  })

  it('demo scan never receives credential fields', async () => {
    const { scanApi } = await import('../../api/client')
    const spy = vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce({
      scan_id: 'demo-001',
      timestamp: new Date().toISOString(),
      simulated: true,
      region: 'eu-north-1',
      findings: [],
      warnings: [],
      summary: {},
      aws_account_id: null,
      aws_identity_arn: null,
    })

    act(() => { useScanStore.setState({ selectedMode: 'demo' }) })

    await act(async () => {
      await useScanStore.getState().triggerScan(undefined, FAKE_CREDS)
    })

    const callArg = spy.mock.calls[0][0]
    expect(callArg.aws_access_key_id).toBeUndefined()
    expect(callArg.aws_secret_access_key).toBeUndefined()
    expect(callArg.aws_session_token).toBeUndefined()
    expect(callArg.mode).toBe('demo')
  })

  it('uses aws_profile (not explicit creds) when no creds provided', async () => {
    const { scanApi } = await import('../../api/client')
    const spy = vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockLiveScanResult())

    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        awsProfile: 'cloudguard',
        awsRegion: 'eu-north-1',
        verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
        identityStatus: 'verified',
      })
    })

    await act(async () => {
      await useScanStore.getState().triggerScan()  // no explicitCreds
    })

    const callArg = spy.mock.calls[0][0]
    expect(callArg.aws_profile).toBe('cloudguard')
    expect(callArg.aws_access_key_id).toBeUndefined()
  })

  it('scan result is stored correctly after successful explicit-cred scan', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockLiveScanResult())

    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        verifiedFor: { profile: 'default', region: 'eu-north-1', verificationGen: 1 },
        awsProfile: 'default',
        awsRegion: 'eu-north-1',
        identityStatus: 'verified',
      })
    })

    await act(async () => {
      await useScanStore.getState().triggerScan(undefined, FAKE_CREDS)
    })

    const state = useScanStore.getState()
    expect(state.status).toBe('complete')
    expect(state.scanResult?.simulated).toBe(false)
    expect(state.scanResult?.scan_id).toBe('live-001')
  })
})

// ---------------------------------------------------------------------------
// Live scan persistence regression (must remain unaffected)
// ---------------------------------------------------------------------------

describe('live scan persistence regression with explicit creds', () => {
  it('live result is not wiped by loadProfiles after explicit-cred scan', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'listProfiles').mockResolvedValueOnce({
      profiles: ['default', 'cloudguard'],
      default_profile: 'cloudguard',
      discovery_error: null,
    })

    // Simulate a completed live scan
    act(() => {
      useScanStore.setState({
        awsProfile: 'default',
        status: 'complete',
        scanResult: mockLiveScanResult(),
        selectedMode: 'live',
      })
    })

    // loadProfiles fires (e.g. if somehow called)
    await act(async () => {
      await useScanStore.getState().loadProfiles()
    })

    // scanResult must NOT be wiped (the fix: shouldUpdateProfile requires scanResult===null)
    expect(useScanStore.getState().scanResult).not.toBeNull()
    expect(useScanStore.getState().scanResult?.scan_id).toBe('live-001')
    expect(useScanStore.getState().status).toBe('complete')
  })
})
