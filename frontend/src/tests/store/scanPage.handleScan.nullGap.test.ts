/**
 * Regression tests for ScanPage handleScan() null-gap bug.
 *
 * Bug: when verifiedCreds === null (never verified or cleared after cred
 * change), the old guard `if (verifiedCreds && ...)` fell through because
 * `null` is falsy — the `if` body was skipped, and triggerScan was called
 * with unverified credentials.
 *
 * Fix: changed the condition to `verifiedCreds === null || <mismatch>` so
 * that null explicitly blocks the scan.
 *
 * These tests exercise the underlying store guard (triggerScan requires
 * verifiedFor !== null for live scans), which is the mechanism that
 * handleScan delegates to after the local verifiedCreds check.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act } from '@testing-library/react'
import { useScanStore } from '../../store/scanStore'
import type { IdentityInfo, ScanResult } from '../../types/findings'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CREDS_A = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  sessionToken: undefined,
}

function mockIdentityInfo(): IdentityInfo {
  return {
    account_id: '316658062107',
    arn: 'arn:aws:sts::316658062107:assumed-role/CloudGuardRole/session',
    user_id: 'AROAEXAMPLE:session',
    region: 'eu-north-1',
    profile: null,
  }
}

function mockLiveResult(): ScanResult {
  return {
    scan_id: 'live-001',
    timestamp: new Date().toISOString(),
    simulated: false,
    region: 'eu-north-1',
    findings: [],
    warnings: [],
    summary: {},
    aws_account_id: '316658062107',
    aws_identity_arn: 'arn:aws:sts::316658062107:assumed-role/Role/s',
  }
}

const INITIAL_STATE = {
  status: 'idle' as const,
  scanResult: null,
  error: null,
  lastScanAt: null,
  selectedMode: 'live' as const,
  liveModeAvailable: true,
  profiles: [],
  profilesLoading: false,
  profilesError: null,
  regionList: [],
  regionsLoading: false,
  regionsError: null,
  enabledRegionsAvailable: false,
  identityStatus: 'idle' as const,
  identityInfo: null,
  identityError: null,
  identityErrorCode: null,
  verifiedFor: null,
  awsProfile: 'default',
  awsRegion: 'eu-north-1',
  regionMode: 'single' as const,
  selectedRegions: ['eu-north-1'],
}

beforeEach(() => {
  act(() => { useScanStore.setState(INITIAL_STATE) })
})

// ---------------------------------------------------------------------------
// Regression: null verifiedCreds / verifiedFor must block live scan
// ---------------------------------------------------------------------------

describe('handleScan null-gap regression (verifiedCreds === null blocks scan)', () => {
  it('blocks the scan API call when verifiedFor is null (never verified)', async () => {
    // verifiedFor is null from INITIAL_STATE — no checkIdentity has been called
    const { scanApi } = await import('../../api/client')
    const triggerSpy = vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockLiveResult())

    await act(async () => {
      await useScanStore.getState().triggerScan(undefined, CREDS_A)
    })

    // Must not hit the API
    expect(triggerSpy).not.toHaveBeenCalled()
    // Store transitions to error to surface the problem to the UI
    expect(useScanStore.getState().status).toBe('error')
    expect(useScanStore.getState().error).toMatch(/re-verify|verified/i)
  })

  it('blocks the scan API call after clearIdentity() nullifies verifiedFor', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentityInfo())
    const triggerSpy = vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockLiveResult())

    // Verify credentials
    await act(async () => { await useScanStore.getState().checkIdentity(CREDS_A) })
    expect(useScanStore.getState().identityStatus).toBe('verified')

    // Simulate credential change in ScanPage (clearIdentity is called by handleCredsChange)
    act(() => { useScanStore.getState().clearIdentity() })
    expect(useScanStore.getState().verifiedFor).toBeNull()

    // Now attempt to scan — should be blocked
    await act(async () => { await useScanStore.getState().triggerScan(undefined, CREDS_A) })

    expect(triggerSpy).not.toHaveBeenCalled()
    expect(useScanStore.getState().status).toBe('error')
  })

  it('allows the scan API call only after successful checkIdentity', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'checkIdentity').mockResolvedValueOnce(mockIdentityInfo())
    const triggerSpy = vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockLiveResult())

    // Verify then scan
    await act(async () => { await useScanStore.getState().checkIdentity(CREDS_A) })
    await act(async () => { await useScanStore.getState().triggerScan(undefined, CREDS_A) })

    expect(triggerSpy).toHaveBeenCalledOnce()
    expect(useScanStore.getState().status).toBe('complete')
    expect(useScanStore.getState().scanResult?.simulated).toBe(false)
  })
})
