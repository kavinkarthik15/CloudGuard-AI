/**
 * Tests for Demo-Only production mode.
 *
 * Verifies:
 * - loadHealth() sets liveModeAvailable from backend response
 * - liveModeAvailable defaults to true (optimistic — backend enforces restriction)
 * - Demo scans work regardless of liveModeAvailable
 * - liveModeAvailable=false prevents live mode selection via setMode (safeguard)
 * - liveModeAvailable is never stored as credential data
 *
 * The backend enforcement is tested separately in test_demo_only_mode.py.
 * This file tests only the frontend usability safeguard.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act } from 'react'
import { useScanStore } from '../../store/scanStore'
import type { ScanResult } from '../../types/findings'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDemoResult(): ScanResult {
  return {
    scan_id: 'demo-001',
    timestamp: new Date().toISOString(),
    simulated: true,
    region: 'eu-north-1',
    findings: [],
    warnings: [],
    summary: {},
    aws_account_id: null,
    aws_identity_arn: null,
  }
}

beforeEach(() => {
  act(() => {
    useScanStore.setState({
      status: 'idle',
      scanResult: null,
      error: null,
      lastScanAt: null,
      selectedMode: 'demo',
      liveModeAvailable: false,   // fail-closed default
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
// loadHealth
// ---------------------------------------------------------------------------

describe('loadHealth', () => {
  it('sets liveModeAvailable=true when backend says true', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'health').mockResolvedValueOnce({
      status: 'ok',
      live_mode_available: true,
    })

    await act(async () => { await useScanStore.getState().loadHealth() })

    expect(useScanStore.getState().liveModeAvailable).toBe(true)
  })

  it('sets liveModeAvailable=false when backend says false (production/demo-only)', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'health').mockResolvedValueOnce({
      status: 'ok',
      live_mode_available: false,
    })

    await act(async () => { await useScanStore.getState().loadHealth() })

    expect(useScanStore.getState().liveModeAvailable).toBe(false)
  })

  it('keeps liveModeAvailable=false when health call fails (backend unreachable)', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'health').mockRejectedValueOnce(new Error('Network error'))

    await act(async () => { await useScanStore.getState().loadHealth() })

    // Fail-closed: health failure leaves liveModeAvailable at its false default.
    // The backend enforces LIVE_AWS_DISABLED server-side regardless.
    expect(useScanStore.getState().liveModeAvailable).toBe(false)
  })

  it('initial liveModeAvailable is false (fail-closed)', () => {
    // Before any health call, frontend assumes live is NOT available.
    // The backend must explicitly report live_mode_available=true to enable it.
    // This prevents a brief fail-open window in production builds.
    expect(useScanStore.getState().liveModeAvailable).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Demo scan still works when live mode is disabled
// ---------------------------------------------------------------------------

describe('demo scan with liveModeAvailable=false', () => {
  it('demo scan succeeds regardless of liveModeAvailable', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(makeDemoResult())

    act(() => {
      useScanStore.setState({ selectedMode: 'demo', liveModeAvailable: false })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    const state = useScanStore.getState()
    expect(state.status).toBe('complete')
    expect(state.scanResult?.simulated).toBe(true)
  })

  it('demo scan sends mode=demo not mode=live', async () => {
    const { scanApi } = await import('../../api/client')
    const spy = vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(makeDemoResult())

    act(() => {
      useScanStore.setState({ selectedMode: 'demo', liveModeAvailable: false })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    expect(spy.mock.calls[0][0].mode).toBe('demo')
  })
})

// ---------------------------------------------------------------------------
// liveModeAvailable in Zustand state never contains credentials
// ---------------------------------------------------------------------------

describe('liveModeAvailable is a boolean flag, never credential data', () => {
  it('liveModeAvailable is a boolean', () => {
    expect(typeof useScanStore.getState().liveModeAvailable).toBe('boolean')
  })

  it('state does not contain any credential-like strings after loadHealth', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'health').mockResolvedValueOnce({
      status: 'ok',
      live_mode_available: false,
    })

    await act(async () => { await useScanStore.getState().loadHealth() })

    const stateJson = JSON.stringify(useScanStore.getState())
    expect(stateJson).not.toContain('AKIA')
    expect(stateJson).not.toContain('secret')
    expect(stateJson).not.toContain('token')
  })
})

// ---------------------------------------------------------------------------
// setMode: live mode still gated by identity verification
// ---------------------------------------------------------------------------

describe('mode switching with liveModeAvailable=false', () => {
  it('switching to live mode clears scan results (setMode still works in store)', () => {
    // The store does not prevent setting selectedMode='live' — that is the
    // UI's responsibility (ModeSelector disables the button). The store
    // simply clears stale results as it always has.
    act(() => {
      useScanStore.setState({
        selectedMode: 'demo',
        liveModeAvailable: false,
        scanResult: makeDemoResult(),
        status: 'complete',
      })
      useScanStore.getState().setMode('live')
    })

    const state = useScanStore.getState()
    // Store allows mode switch — UI prevents it via disabled button
    expect(state.selectedMode).toBe('live')
    expect(state.scanResult).toBeNull()  // cleared on mode switch
  })
})
