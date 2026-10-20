/**
 * Phase 4C tests — AWS Session and Identity Reliability
 *
 * Covers:
 *   - Profile switch clears identity (including error state) and scan results
 *   - Region switch clears identity and scan results
 *   - Stale async response is discarded after profile change
 *   - SESSION_EXPIRED and NO_CREDENTIALS error codes are stored in identityErrorCode
 *   - Demo Mode switch never leaves live identity state
 *   - Demo Mode does not trigger checkIdentity
 *
 * Classification: MOCKED — all scanApi calls are vi.spyOn mocks.
 * No real AWS API calls are made.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act } from 'react'
import { useScanStore } from '../../store/scanStore'
import { ApiError } from '../../api/client'
import type { IdentityInfo, ScanResult } from '../../types/findings'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockIdentity(profile = 'profile-a', region = 'eu-north-1'): IdentityInfo {
  return {
    account_id: '123456789012',
    arn: `arn:aws:sts::123456789012:assumed-role/TestRole/${profile}`,
    user_id: 'AROAEXAMPLE:session',
    region,
    profile,
  }
}

function mockScanResult(simulated = false): ScanResult {
  return {
    scan_id: `scan-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: new Date().toISOString(),
    simulated,
    region: 'eu-north-1',
    findings: [],
    warnings: [],
    summary: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
    aws_account_id: simulated ? null : '123456789012',
    aws_identity_arn: simulated ? null : 'arn:aws:sts::123456789012:assumed-role/R/s',
  }
}

// Reset the entire store to a clean live-mode state before each test
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
      awsProfile: 'profile-a',
      awsRegion: 'eu-north-1',
    })
  })
})

// ---------------------------------------------------------------------------
// Profile switch behaviour (Phase 4C requirement 2g)
// ---------------------------------------------------------------------------

describe('setAwsProfile — Phase 4C', () => {
  it('clears verified identity and scan result when switching profiles', () => {
    act(() => {
      useScanStore.setState({
        awsProfile: 'profile-a',
        identityStatus: 'verified',
        identityInfo: mockIdentity('profile-a'),
        identityErrorCode: null,
        verifiedFor: { profile: 'profile-a', region: 'eu-north-1' },
        scanResult: mockScanResult(false),
        status: 'complete',
      })
    })

    act(() => useScanStore.getState().setAwsProfile('profile-b'))

    const state = useScanStore.getState()
    expect(state.awsProfile).toBe('profile-b')
    expect(state.identityStatus).toBe('idle')
    expect(state.identityInfo).toBeNull()
    expect(state.identityError).toBeNull()
    expect(state.identityErrorCode).toBeNull()
    expect(state.verifiedFor).toBeNull()
    expect(state.scanResult).toBeNull()
    expect(state.status).toBe('idle')
  })

  it('clears identity error state even when verifiedFor is null', () => {
    // Bug from plan: old code only cleared identity when verifiedFor !== null.
    // Phase 4C requires clearing even when the previous attempt left an error
    // and verifiedFor is null.
    act(() => {
      useScanStore.setState({
        awsProfile: 'profile-a',
        identityStatus: 'error',
        identityError: 'SSO session expired for profile-a',
        identityErrorCode: 'SESSION_EXPIRED',
        verifiedFor: null,   // <-- this is the case the bug affected
        identityInfo: null,
      })
    })

    act(() => useScanStore.getState().setAwsProfile('profile-b'))

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('idle')
    expect(state.identityError).toBeNull()
    expect(state.identityErrorCode).toBeNull()
  })

  it('is a no-op when setting the same profile', () => {
    act(() => {
      useScanStore.setState({
        awsProfile: 'profile-a',
        identityStatus: 'verified',
        identityInfo: mockIdentity('profile-a'),
        verifiedFor: { profile: 'profile-a', region: 'eu-north-1' },
        scanResult: mockScanResult(false),
        status: 'complete',
      })
    })

    act(() => useScanStore.getState().setAwsProfile('profile-a'))

    // No change
    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('verified')
    expect(state.scanResult).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Region switch behaviour (Phase 4C)
// ---------------------------------------------------------------------------

describe('setAwsRegion — Phase 4C', () => {
  it('clears identity and scan result when switching regions', () => {
    act(() => {
      useScanStore.setState({
        awsRegion: 'eu-north-1',
        identityStatus: 'verified',
        identityInfo: mockIdentity('profile-a', 'eu-north-1'),
        verifiedFor: { profile: 'profile-a', region: 'eu-north-1' },
        scanResult: mockScanResult(false),
        status: 'complete',
      })
    })

    act(() => useScanStore.getState().setAwsRegion('us-east-1'))

    const state = useScanStore.getState()
    expect(state.awsRegion).toBe('us-east-1')
    expect(state.identityStatus).toBe('idle')
    expect(state.verifiedFor).toBeNull()
    expect(state.scanResult).toBeNull()
    expect(state.identityErrorCode).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Stale response guard (Phase 4C requirement 2h)
// ---------------------------------------------------------------------------

describe('checkIdentity — stale response guard', () => {
  it('discards an identity response that arrived after a profile switch', async () => {
    const { scanApi } = await import('../../api/client')

    // Create a deferred promise so we can control when checkIdentity resolves
    let resolveIdentity!: (value: IdentityInfo) => void
    const deferredIdentity = new Promise<IdentityInfo>((res) => {
      resolveIdentity = res
    })

    vi.spyOn(scanApi, 'checkIdentity').mockReturnValueOnce(deferredIdentity)

    // Start identity check for profile-a (does not await)
    act(() => {
      useScanStore.setState({ awsProfile: 'profile-a', awsRegion: 'eu-north-1' })
    })
    // Kick off the async call — don't await it
    const checkPromise = useScanStore.getState().checkIdentity()

    // Switch profile BEFORE the response arrives
    act(() => useScanStore.getState().setAwsProfile('profile-b'))

    // Now resolve the deferred promise with profile-a's identity
    await act(async () => {
      resolveIdentity(mockIdentity('profile-a'))
      await checkPromise
    })

    // The stale result for profile-a must be discarded
    const state = useScanStore.getState()
    expect(state.awsProfile).toBe('profile-b')
    expect(state.identityStatus).toBe('idle')  // reset by setAwsProfile, not overwritten
    expect(state.identityInfo).toBeNull()
    expect(state.verifiedFor).toBeNull()
  })

  it('discards a stale error response after a profile switch', async () => {
    const { scanApi } = await import('../../api/client')

    let rejectIdentity!: (reason: unknown) => void
    const deferredError = new Promise<IdentityInfo>((_, rej) => {
      rejectIdentity = rej
    })

    vi.spyOn(scanApi, 'checkIdentity').mockReturnValueOnce(deferredError)

    act(() => {
      useScanStore.setState({ awsProfile: 'profile-a', awsRegion: 'eu-north-1' })
    })
    const checkPromise = useScanStore.getState().checkIdentity()

    // Switch profile before the error arrives
    act(() => useScanStore.getState().setAwsProfile('profile-b'))

    // Now reject with SESSION_EXPIRED for profile-a
    await act(async () => {
      rejectIdentity(new ApiError('SESSION_EXPIRED', 'SSO expired for profile-a'))
      await checkPromise
    })

    // Stale error must be discarded — state should reflect profile-b's idle state
    const state = useScanStore.getState()
    expect(state.awsProfile).toBe('profile-b')
    expect(state.identityStatus).toBe('idle')
    expect(state.identityError).toBeNull()
    expect(state.identityErrorCode).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Error code storage (Phase 4C requirement 2i)
// ---------------------------------------------------------------------------

describe('checkIdentity — error codes stored in identityErrorCode', () => {
  it('stores SESSION_EXPIRED code on session expired error', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockRejectedValueOnce(
      new ApiError('SESSION_EXPIRED', 'AWS SSO session expired. Run: aws sso login --profile test')
    )

    useScanStore.setState({ awsProfile: 'test', awsRegion: 'eu-north-1' })
    await act(async () => { await useScanStore.getState().checkIdentity() })

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('error')
    expect(state.identityErrorCode).toBe('SESSION_EXPIRED')
    expect(state.identityError).toContain('sso login')
  })

  it('stores NO_CREDENTIALS code on missing credentials error', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockRejectedValueOnce(
      new ApiError('NO_CREDENTIALS', "No credentials found for profile 'ghost'. Run: aws configure")
    )

    useScanStore.setState({ awsProfile: 'ghost', awsRegion: 'eu-north-1' })
    await act(async () => { await useScanStore.getState().checkIdentity() })

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('error')
    expect(state.identityErrorCode).toBe('NO_CREDENTIALS')
    expect(state.identityError).toContain('configure')
  })

  it('stores NETWORK_ERROR code on network failure', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockRejectedValueOnce(
      new ApiError('NETWORK_ERROR', 'Could not reach AWS. Check internet connectivity.')
    )

    useScanStore.setState({ awsProfile: 'test', awsRegion: 'eu-north-1' })
    await act(async () => { await useScanStore.getState().checkIdentity() })

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('error')
    expect(state.identityErrorCode).toBe('NETWORK_ERROR')
  })

  it('stores INSUFFICIENT_PERMISSIONS code on access denied', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockRejectedValueOnce(
      new ApiError('INSUFFICIENT_PERMISSIONS', 'sts:GetCallerIdentity was denied. Check IAM permissions.')
    )

    useScanStore.setState({ awsProfile: 'restricted', awsRegion: 'eu-north-1' })
    await act(async () => { await useScanStore.getState().checkIdentity() })

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('error')
    expect(state.identityErrorCode).toBe('INSUFFICIENT_PERMISSIONS')
  })

  it('identityErrorCode is null on successful verification', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentity())

    useScanStore.setState({ awsProfile: 'profile-a', awsRegion: 'eu-north-1' })
    await act(async () => { await useScanStore.getState().checkIdentity() })

    const state = useScanStore.getState()
    expect(state.identityStatus).toBe('verified')
    expect(state.identityErrorCode).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Demo Mode independence (Phase 4C requirement 2j)
// ---------------------------------------------------------------------------

describe('Demo Mode — independence from AWS credentials', () => {
  it('switching to Demo Mode clears all live identity state', () => {
    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        identityStatus: 'verified',
        identityInfo: mockIdentity(),
        identityErrorCode: null,
        verifiedFor: { profile: 'profile-a', region: 'eu-north-1' },
        scanResult: mockScanResult(false),
        status: 'complete',
      })
    })

    act(() => useScanStore.getState().setMode('demo'))

    const state = useScanStore.getState()
    expect(state.selectedMode).toBe('demo')
    expect(state.identityStatus).toBe('idle')
    expect(state.identityInfo).toBeNull()
    expect(state.identityError).toBeNull()
    expect(state.identityErrorCode).toBeNull()
    expect(state.verifiedFor).toBeNull()
    expect(state.scanResult).toBeNull()
  })

  it('demo scan does not call checkIdentity or /api/identity', async () => {
    const { scanApi } = await import('../../api/client')
    const checkIdentitySpy = vi.spyOn(scanApi, 'checkIdentity')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockScanResult(true))

    act(() => useScanStore.getState().setMode('demo'))
    await act(async () => { await useScanStore.getState().triggerScan() })

    expect(checkIdentitySpy).not.toHaveBeenCalled()
    expect(useScanStore.getState().scanResult?.simulated).toBe(true)
  })
})
