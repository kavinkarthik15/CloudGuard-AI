/**
 * Tests for the Zustand scan store — mode switching, identity state,
 * result provenance, stale-result clearing, and Phase 4A profile loading.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act } from 'react'
import { useScanStore, selectIsIdentityCurrentlyValid } from '../../store/scanStore'
import type { IdentityInfo, ScanResult } from '../../types/findings'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockScanResult(simulated: boolean, scanId?: string): ScanResult {
  return {
    scan_id: scanId ?? `scan-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: new Date().toISOString(),
    simulated,
    region: 'eu-north-1',
    findings: simulated
      ? [{ id: 'f1', resource_type: 'S3Bucket', resource_name: 'demo-bucket', severity: 'High',
           title: 'Demo finding', evidence: {}, risk_explanation: 'simulated', remediation: 'fix', simulated: true }]
      : [],
    warnings: [],
    summary: { Critical: 0, High: simulated ? 1 : 0, Medium: 0, Low: 0, Informational: 0 },
    aws_account_id: simulated ? null : '123456789012',
    aws_identity_arn: simulated ? null : 'arn:aws:sts::123456789012:assumed-role/R/s',
  }
}

function mockIdentity(profile = 'cloudguard', region = 'eu-north-1'): IdentityInfo {
  return {
    account_id: '123456789012',
    arn: 'arn:aws:sts::123456789012:assumed-role/CloudGuardRole/session',
    user_id: 'AROAEXAMPLE:session',
    region,
    profile,
  }
}

// Reset store before each test
beforeEach(() => {
  const store = useScanStore.getState()
  act(() => {
    store.setMode('demo')
    store.clearError()
    store.clearIdentity()
    // Reset profiles state
    useScanStore.setState({ profiles: [], profilesLoading: false, profilesError: null })
  })
})

// ---------------------------------------------------------------------------
// Mode switching
// ---------------------------------------------------------------------------

describe('setMode', () => {
  it('switches from demo to live', () => {
    act(() => useScanStore.getState().setMode('live'))
    expect(useScanStore.getState().selectedMode).toBe('live')
  })

  it('switching modes clears scan result', async () => {
    useScanStore.setState({ scanResult: mockScanResult(true), status: 'complete' })
    expect(useScanStore.getState().scanResult).not.toBeNull()

    act(() => useScanStore.getState().setMode('live'))

    expect(useScanStore.getState().scanResult).toBeNull()
    expect(useScanStore.getState().status).toBe('idle')
  })

  it('switching modes clears error state', () => {
    useScanStore.setState({ error: 'previous error', status: 'error' })
    act(() => useScanStore.getState().setMode('live'))
    expect(useScanStore.getState().error).toBeNull()
  })

  it('switching from live to demo clears identity state and verifiedFor', () => {
    useScanStore.setState({
      selectedMode: 'live',
      identityStatus: 'verified',
      identityInfo: mockIdentity(),
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
    })
    act(() => useScanStore.getState().setMode('demo'))
    expect(useScanStore.getState().identityStatus).toBe('idle')
    expect(useScanStore.getState().identityInfo).toBeNull()
    expect(useScanStore.getState().verifiedFor).toBeNull()
  })

  it('switching to the same mode is a no-op', () => {
    useScanStore.setState({ scanResult: mockScanResult(true), status: 'complete' })
    act(() => useScanStore.getState().setMode('demo'))
    expect(useScanStore.getState().scanResult).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Profile change clears identity (Phase 4A)
// ---------------------------------------------------------------------------

describe('setAwsProfile', () => {
  it('changing profile clears verifiedFor and identity when verified for different profile', () => {
    useScanStore.setState({
      awsProfile: 'cloudguard',
      awsRegion: 'eu-north-1',
      identityStatus: 'verified',
      identityInfo: mockIdentity('cloudguard'),
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
    })

    act(() => useScanStore.getState().setAwsProfile('staging'))

    const state = useScanStore.getState()
    expect(state.awsProfile).toBe('staging')
    expect(state.identityStatus).toBe('idle')
    expect(state.verifiedFor).toBeNull()
  })

  it('setting the same profile does not clear identity', () => {
    useScanStore.setState({
      awsProfile: 'cloudguard',
      identityStatus: 'verified',
      identityInfo: mockIdentity('cloudguard'),
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
    })

    act(() => useScanStore.getState().setAwsProfile('cloudguard'))

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('verified')
    expect(state.verifiedFor).not.toBeNull()
  })
})

describe('setAwsRegion', () => {
  it('changing region clears verifiedFor and identity when verified for different region', () => {
    useScanStore.setState({
      awsProfile: 'cloudguard',
      awsRegion: 'eu-north-1',
      identityStatus: 'verified',
      identityInfo: mockIdentity('cloudguard', 'eu-north-1'),
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
    })

    act(() => useScanStore.getState().setAwsRegion('us-east-1'))

    const state = useScanStore.getState()
    expect(state.awsRegion).toBe('us-east-1')
    expect(state.identityStatus).toBe('idle')
    expect(state.verifiedFor).toBeNull()
  })

  it('setting the same region does not clear identity', () => {
    useScanStore.setState({
      awsRegion: 'eu-north-1',
      identityStatus: 'verified',
      identityInfo: mockIdentity('cloudguard', 'eu-north-1'),
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
    })

    act(() => useScanStore.getState().setAwsRegion('eu-north-1'))

    expect(useScanStore.getState().identityStatus).toBe('verified')
  })
})

// ---------------------------------------------------------------------------
// Identity validity selector (Phase 4A)
// ---------------------------------------------------------------------------

describe('selectIsIdentityCurrentlyValid', () => {
  it('returns true when verified for current profile and region', () => {
    useScanStore.setState({
      identityStatus: 'verified',
      identityInfo: mockIdentity(),
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
      awsProfile: 'cloudguard',
      awsRegion: 'eu-north-1',
    })
    expect(selectIsIdentityCurrentlyValid(useScanStore.getState())).toBe(true)
  })

  it('returns false when profile changed since verification', () => {
    useScanStore.setState({
      identityStatus: 'verified',
      identityInfo: mockIdentity('cloudguard'),
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
      awsProfile: 'staging',          // profile changed
      awsRegion: 'eu-north-1',
    })
    expect(selectIsIdentityCurrentlyValid(useScanStore.getState())).toBe(false)
  })

  it('returns false when region changed since verification', () => {
    useScanStore.setState({
      identityStatus: 'verified',
      identityInfo: mockIdentity(),
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
      awsProfile: 'cloudguard',
      awsRegion: 'us-east-1',          // region changed
    })
    expect(selectIsIdentityCurrentlyValid(useScanStore.getState())).toBe(false)
  })

  it('returns false when verifiedFor is null', () => {
    useScanStore.setState({
      identityStatus: 'verified',
      identityInfo: mockIdentity(),
      verifiedFor: null,
      awsProfile: 'cloudguard',
      awsRegion: 'eu-north-1',
    })
    expect(selectIsIdentityCurrentlyValid(useScanStore.getState())).toBe(false)
  })

  it('returns false when identityStatus is not verified', () => {
    useScanStore.setState({
      identityStatus: 'checking',
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
      awsProfile: 'cloudguard',
      awsRegion: 'eu-north-1',
    })
    expect(selectIsIdentityCurrentlyValid(useScanStore.getState())).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// loadProfiles (Phase 4A)
// ---------------------------------------------------------------------------

describe('loadProfiles', () => {
  it('populates profiles on success', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'listProfiles').mockResolvedValueOnce({
      profiles: ['default', 'cloudguard', 'staging'],
      default_profile: null,
      discovery_error: null,
    })

    await act(async () => { await useScanStore.getState().loadProfiles() })

    const state = useScanStore.getState()
    expect(state.profiles).toContain('cloudguard')
    expect(state.profiles).toContain('staging')
    expect(state.profilesLoading).toBe(false)
    expect(state.profilesError).toBeNull()
  })

  it('sets profilesError when discovery_error is returned', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'listProfiles').mockResolvedValueOnce({
      profiles: [],
      default_profile: null,
      discovery_error: 'Permission denied reading ~/.aws/config',
    })

    await act(async () => { await useScanStore.getState().loadProfiles() })

    const state = useScanStore.getState()
    expect(state.profiles).toEqual([])
    expect(state.profilesError).toContain('Permission denied')
    expect(state.profilesLoading).toBe(false)
  })

  it('sets profilesError on network failure', async () => {
    const { ApiError, scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'listProfiles').mockRejectedValueOnce(
      new ApiError('NETWORK_ERROR', 'Backend is not running')
    )

    await act(async () => { await useScanStore.getState().loadProfiles() })

    const state = useScanStore.getState()
    expect(state.profilesError).toContain('Backend is not running')
    expect(state.profilesLoading).toBe(false)
  })

  it('profiles list never contains credential-like values', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'listProfiles').mockResolvedValueOnce({
      profiles: ['default', 'prod-account', 'my-org'],
      default_profile: null,
      discovery_error: null,
    })

    await act(async () => { await useScanStore.getState().loadProfiles() })

    const { profiles } = useScanStore.getState()
    for (const p of profiles) {
      expect(p).not.toMatch(/AKIA|ASIA|secret|password/i)
    }
  })
})

// ---------------------------------------------------------------------------
// Identity state
// ---------------------------------------------------------------------------

describe('checkIdentity', () => {
  it('transitions through checking → verified on success and sets verifiedFor', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentity())

    useScanStore.setState({ selectedMode: 'live', awsProfile: 'cloudguard', awsRegion: 'eu-north-1' })

    await act(async () => { await useScanStore.getState().checkIdentity() })

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('verified')
    expect(state.identityInfo?.account_id).toBe('123456789012')
    expect(state.identityError).toBeNull()
    expect(state.verifiedFor).toEqual({ profile: 'cloudguard', region: 'eu-north-1', verificationGen: expect.any(Number) })
  })

  it('transitions through checking → error on auth failure', async () => {
    const { ApiError, scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockRejectedValueOnce(
      new ApiError('INVALID_CREDENTIALS', 'SSO session expired')
    )

    useScanStore.setState({ selectedMode: 'live', awsProfile: 'cloudguard', awsRegion: 'eu-north-1' })

    await act(async () => { await useScanStore.getState().checkIdentity() })

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('error')
    expect(state.identityError).toContain('SSO session expired')
    expect(state.identityInfo).toBeNull()
    expect(state.verifiedFor).toBeNull()
  })

  it('error message does not expose credentials', async () => {
    const { ApiError, scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockRejectedValueOnce(
      new ApiError('INVALID_CREDENTIALS', 'Token expired for profile cloudguard')
    )

    useScanStore.setState({ selectedMode: 'live', awsProfile: 'cloudguard', awsRegion: 'eu-north-1' })
    await act(async () => { await useScanStore.getState().checkIdentity() })

    const { identityError } = useScanStore.getState()
    expect(identityError).not.toMatch(/AKIA|secret|password|token-value/i)
  })
})

describe('clearIdentity', () => {
  it('resets identity state to idle and clears verifiedFor', () => {
    useScanStore.setState({
      identityStatus: 'verified',
      identityInfo: mockIdentity(),
      identityError: null,
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
    })
    act(() => useScanStore.getState().clearIdentity())
    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('idle')
    expect(state.identityInfo).toBeNull()
    expect(state.verifiedFor).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// triggerScan — result provenance
// ---------------------------------------------------------------------------

describe('triggerScan', () => {
  it('demo scan result has simulated=true', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockScanResult(true))

    useScanStore.setState({ selectedMode: 'demo' })
    await act(async () => { await useScanStore.getState().triggerScan() })

    const { scanResult } = useScanStore.getState()
    expect(scanResult?.simulated).toBe(true)
    expect(scanApi.triggerScan).toHaveBeenCalledWith(
      expect.objectContaining({ mode: 'demo' })
    )
  })

  it('live scan result has simulated=false', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockScanResult(false))

    useScanStore.setState({
      selectedMode: 'live',
      awsProfile: 'cloudguard',
      awsRegion: 'eu-north-1',
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
      identityStatus: 'verified',
    })
    await act(async () => { await useScanStore.getState().triggerScan() })

    const { scanResult } = useScanStore.getState()
    expect(scanResult?.simulated).toBe(false)
    expect(scanApi.triggerScan).toHaveBeenCalledWith(
      expect.objectContaining({ mode: 'live', aws_profile: 'cloudguard' })
    )
  })

  it('live scan blocked when identity not verified for current settings', async () => {
    const { scanApi } = await import('../../api/client')
    const spy = vi.spyOn(scanApi, 'triggerScan')

    useScanStore.setState({
      selectedMode: 'live',
      awsProfile: 'cloudguard',
      awsRegion: 'eu-north-1',
      verifiedFor: null,              // not verified
      identityStatus: 'idle',
    })
    await act(async () => { await useScanStore.getState().triggerScan() })

    expect(spy).not.toHaveBeenCalled()
    expect(useScanStore.getState().status).toBe('error')
    expect(useScanStore.getState().error).toContain('re-verify')
  })

  it('failed live scan does not store a result', async () => {
    const { ApiError, scanApi } = await import('../../api/client')

    act(() => useScanStore.getState().setMode('live'))
    // Set verifiedFor so the pre-check passes, but scan still fails
    useScanStore.setState({
      verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
      awsProfile: 'cloudguard',
      awsRegion: 'eu-north-1',
      identityStatus: 'verified',
    })

    vi.spyOn(scanApi, 'triggerScan').mockRejectedValueOnce(
      new ApiError('INVALID_CREDENTIALS', 'Auth failed')
    )

    await act(async () => { await useScanStore.getState().triggerScan() })

    const state = useScanStore.getState()
    expect(state.status).toBe('error')
    expect(state.scanResult).toBeNull()
    expect(state.error).toContain('Auth failed')
    // Auth failure during scan clears verifiedFor
    expect(state.verifiedFor).toBeNull()
  })

  it('status transitions idle → scanning → complete', async () => {
    const { scanApi } = await import('../../api/client')
    const statuses: string[] = []

    useScanStore.subscribe((s) => statuses.push(s.status))

    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockScanResult(true))
    useScanStore.setState({ selectedMode: 'demo', status: 'idle' })

    await act(async () => { await useScanStore.getState().triggerScan() })

    expect(statuses).toContain('scanning')
    expect(useScanStore.getState().status).toBe('complete')
  })
})

// ---------------------------------------------------------------------------
// Export consistency
// ---------------------------------------------------------------------------

describe('export provenance', () => {
  it('scan_id in store matches what was returned by triggerScan', async () => {
    const { scanApi } = await import('../../api/client')
    const expectedResult = mockScanResult(true, 'scan-abc-123')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(expectedResult)

    useScanStore.setState({ selectedMode: 'demo' })
    await act(async () => { await useScanStore.getState().triggerScan() })

    expect(useScanStore.getState().scanResult?.scan_id).toBe('scan-abc-123')
  })
})
