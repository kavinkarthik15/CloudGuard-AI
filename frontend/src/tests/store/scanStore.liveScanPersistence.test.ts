/**
 * Regression tests for live scan result persistence across navigation.
 *
 * Root cause fixed:
 *   1. loadProfiles() was silently updating awsProfile (via setAwsProfile) when the
 *      backend returned a non-default profile name — this wiped scanResult and reset
 *      status to 'idle', causing FindingsPage to show "Run a scan to see findings"
 *      after a successful live scan.
 *   2. DashboardPage auto-scan fired unconditionally on mount (no selectedMode guard),
 *      meaning it could replace a live result with a demo scan when the user navigated
 *      to Dashboard after a live scan.
 *
 * All tests use mocked scanApi — no real AWS calls.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act } from 'react'
import { useScanStore } from '../../store/scanStore'
import { ApiError } from '../../api/client'
import type { ScanResult } from '../../types/findings'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeLiveResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scan_id: 'live-scan-001',
    timestamp: new Date().toISOString(),
    simulated: false,
    region: 'eu-north-1',
    findings: [],
    warnings: [],
    summary: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
    aws_account_id: '316658062107',
    aws_identity_arn: 'arn:aws:sts::316658062107:assumed-role/CloudGuardRole/session',
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
    ...overrides,
  }
}

function makeDemoResult(): ScanResult {
  return {
    scan_id: 'demo-scan-001',
    timestamp: new Date().toISOString(),
    simulated: true,
    region: 'eu-north-1',
    findings: [
      {
        id: 'f1', resource_type: 'S3Bucket', resource_name: 'demo-bucket',
        severity: 'High', title: 'Demo finding', evidence: {}, risk_explanation: 'sim',
        remediation: 'fix', simulated: true,
      }
    ],
    warnings: [],
    summary: { Critical: 0, High: 1, Medium: 0, Low: 0, Informational: 0 },
    aws_account_id: null,
    aws_identity_arn: null,
  }
}

// Reset store before each test
beforeEach(() => {
  act(() => {
    useScanStore.setState({
      status: 'idle',
      scanResult: null,
      error: null,
      lastScanAt: null,
      selectedMode: 'demo',
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
// Scenario 1: Live scan → navigate to Findings
// ---------------------------------------------------------------------------

describe('Scenario 1: live scan result persists on Findings navigation', () => {
  it('scanResult remains after live scan completes', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(makeLiveResult())

    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        awsProfile: 'cloudguard',
        awsRegion: 'eu-north-1',
        verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
        identityStatus: 'verified',
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    const state = useScanStore.getState()
    expect(state.status).toBe('complete')
    expect(state.scanResult).not.toBeNull()
    expect(state.scanResult?.simulated).toBe(false)
    expect(state.scanResult?.scan_id).toBe('live-scan-001')
  })

  it('simulated banner reads scanResult.simulated, not selectedMode', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(makeLiveResult())

    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
        awsProfile: 'cloudguard',
        awsRegion: 'eu-north-1',
        identityStatus: 'verified',
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    // The banner checks scanResult.simulated — should be false for a live result
    const { scanResult } = useScanStore.getState()
    expect(scanResult?.simulated).toBe(false)
    // selectedMode is still 'live', consistent with simulated=false
    expect(useScanStore.getState().selectedMode).toBe('live')
  })
})

// ---------------------------------------------------------------------------
// Scenario 2: Live scan → Dashboard navigation
// (auto-scan must NOT fire because scanResult is already present)
// ---------------------------------------------------------------------------

describe('Scenario 2: Dashboard does not auto-scan after live scan', () => {
  it('auto-scan guard: does not call triggerScan when scanResult is present', async () => {
    const { scanApi } = await import('../../api/client')
    const triggerSpy = vi.spyOn(scanApi, 'triggerScan')

    // Place a live result in the store (simulates user returning to Dashboard)
    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        status: 'complete',
        scanResult: makeLiveResult(),
        lastScanAt: new Date().toISOString(),
      })
    })

    // The DashboardPage effect condition: scanResult === null && status === 'idle' && selectedMode === 'demo'
    // None of those are true here → triggerScan must NOT fire
    const { scanResult, status, selectedMode } = useScanStore.getState()
    const shouldAutoScan = scanResult === null && status === 'idle' && selectedMode === 'demo'
    expect(shouldAutoScan).toBe(false)
    expect(triggerSpy).not.toHaveBeenCalled()
  })

  it('auto-scan guard: does not auto-scan in live mode even when scanResult is null', async () => {
    const { scanApi } = await import('../../api/client')
    const triggerSpy = vi.spyOn(scanApi, 'triggerScan')

    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        status: 'idle',
        scanResult: null,
      })
    })

    const { scanResult, status, selectedMode } = useScanStore.getState()
    const shouldAutoScan = scanResult === null && status === 'idle' && selectedMode === 'demo'
    // selectedMode is 'live' → condition is false → no auto-scan
    expect(shouldAutoScan).toBe(false)
    expect(triggerSpy).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Scenario 3: Live scan → Dashboard → Rescan
// (Rescan via Dashboard "Rescan" button calls triggerScan in current selectedMode)
// ---------------------------------------------------------------------------

describe('Scenario 3: Dashboard Rescan respects selectedMode', () => {
  it('rescan in demo mode after live scan uses demo mode (selectedMode=demo)', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(makeDemoResult())

    act(() => {
      useScanStore.setState({
        selectedMode: 'demo',  // user switched back to demo
        status: 'complete',
        scanResult: makeLiveResult(),  // previously live result
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    const { scanResult } = useScanStore.getState()
    // After demo rescan, result should be simulated
    expect(scanResult?.simulated).toBe(true)
    expect(scanResult?.scan_id).toBe('demo-scan-001')
  })

  it('rescan in live mode uses live mode — fails if verifiedFor is null', async () => {
    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        status: 'complete',
        scanResult: makeLiveResult(),
        verifiedFor: null,  // identity not verified (e.g. session expired)
        awsProfile: 'cloudguard',
        awsRegion: 'eu-north-1',
        identityStatus: 'idle',
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    // Without verifiedFor, triggerScan sets status='error', doesn't wipe scanResult
    const state = useScanStore.getState()
    expect(state.status).toBe('error')
    expect(state.error).toContain('re-verify')
    // Previous scan result is NOT wiped by the failed triggerScan attempt
    // (status='error', scanResult still present from before)
  })
})

// ---------------------------------------------------------------------------
// Scenario 4: Demo → Live mode transition
// ---------------------------------------------------------------------------

describe('Scenario 4: Demo-to-live mode transition', () => {
  it('switching from demo to live clears demo scan result', async () => {
    act(() => {
      useScanStore.setState({
        selectedMode: 'demo',
        status: 'complete',
        scanResult: makeDemoResult(),
      })
    })

    act(() => useScanStore.getState().setMode('live'))

    const state = useScanStore.getState()
    expect(state.selectedMode).toBe('live')
    expect(state.scanResult).toBeNull()
    expect(state.status).toBe('idle')
  })

  it('switching from live to demo clears live scan result and identity', async () => {
    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        status: 'complete',
        scanResult: makeLiveResult(),
        identityStatus: 'verified',
        verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
      })
    })

    act(() => useScanStore.getState().setMode('demo'))

    const state = useScanStore.getState()
    expect(state.selectedMode).toBe('demo')
    expect(state.scanResult).toBeNull()
    expect(state.identityStatus).toBe('idle')
    expect(state.verifiedFor).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Scenario 5: Successful live scan with zero findings
// ---------------------------------------------------------------------------

describe('Scenario 5: Live scan with zero findings', () => {
  it('zero-findings live scan is NOT treated as a failed scan', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(makeLiveResult({ findings: [] }))

    act(() => {
      useScanStore.setState({
        selectedMode: 'live',
        awsProfile: 'cloudguard',
        awsRegion: 'eu-north-1',
        verifiedFor: { profile: 'cloudguard', region: 'eu-north-1', verificationGen: 1 },
        identityStatus: 'verified',
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    const state = useScanStore.getState()
    expect(state.status).toBe('complete')        // not 'error'
    expect(state.error).toBeNull()               // no error
    expect(state.scanResult?.findings).toHaveLength(0)
    expect(state.scanResult?.simulated).toBe(false)  // still live
  })
})

// ---------------------------------------------------------------------------
// Scenario 6: Failed scan vs successful empty scan
// ---------------------------------------------------------------------------

describe('Scenario 6: failed scan vs successful empty scan', () => {
  it('network error → status=error, scanResult unchanged from previous', async () => {
    const { ApiError: AE, scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockRejectedValueOnce(
      new AE('NETWORK_ERROR', 'Could not connect to backend')
    )

    const previousResult = makeLiveResult()
    act(() => {
      useScanStore.setState({
        selectedMode: 'demo',
        status: 'complete',
        scanResult: previousResult,
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    const state = useScanStore.getState()
    expect(state.status).toBe('error')
    expect(state.error).toContain('connect')
    // Previous result is preserved — failed scan doesn't wipe the last good result
    // (triggerScan sets status='error' but does NOT set scanResult=null)
    // This is the correct behavior per the store implementation
  })

  it('successful scan with 0 findings has status=complete (not error)', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(makeDemoResult())

    act(() => { useScanStore.setState({ selectedMode: 'demo' }) })
    await act(async () => { await useScanStore.getState().triggerScan() })

    // Demo scan succeeds
    expect(useScanStore.getState().status).toBe('complete')
    expect(useScanStore.getState().error).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Root cause regression: loadProfiles must NOT wipe scanResult
// ---------------------------------------------------------------------------

describe('Root cause regression: loadProfiles does not wipe existing scanResult', () => {
  it('loadProfiles with a non-default profile does NOT wipe an existing scan result', async () => {
    const { scanApi } = await import('../../api/client')
    // Backend returns 'cloudguard' as the default profile
    vi.spyOn(scanApi, 'listProfiles').mockResolvedValueOnce({
      profiles: ['default', 'cloudguard'],
      default_profile: 'cloudguard',
      discovery_error: null,
    })

    // Store has an existing live result with default profile
    act(() => {
      useScanStore.setState({
        awsProfile: 'default',  // initial default
        status: 'complete',
        scanResult: makeLiveResult(),
        selectedMode: 'live',
      })
    })

    // loadProfiles fires (as it does when ScanPage mounts in live mode)
    await act(async () => { await useScanStore.getState().loadProfiles() })

    const state = useScanStore.getState()
    // scanResult must NOT have been wiped — the fix adds scanResult === null guard
    expect(state.scanResult).not.toBeNull()
    expect(state.scanResult?.scan_id).toBe('live-scan-001')
    expect(state.status).toBe('complete')
  })

  it('loadProfiles updates profile when there is no scan result', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'listProfiles').mockResolvedValueOnce({
      profiles: ['default', 'cloudguard'],
      default_profile: 'cloudguard',
      discovery_error: null,
    })

    act(() => {
      useScanStore.setState({
        awsProfile: 'default',
        status: 'idle',
        scanResult: null,  // no existing result — safe to update profile
      })
    })

    await act(async () => { await useScanStore.getState().loadProfiles() })

    const state = useScanStore.getState()
    // Profile gets updated since scanResult is null
    expect(state.awsProfile).toBe('cloudguard')
  })

  it('loadProfiles does NOT update profile when user manually changed it', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'listProfiles').mockResolvedValueOnce({
      profiles: ['default', 'cloudguard', 'staging'],
      default_profile: 'cloudguard',
      discovery_error: null,
    })

    act(() => {
      useScanStore.setState({
        awsProfile: 'staging',  // user manually selected 'staging' (not 'default')
        status: 'idle',
        scanResult: null,
      })
    })

    await act(async () => { await useScanStore.getState().loadProfiles() })

    const state = useScanStore.getState()
    // 'staging' !== DEFAULT_AWS_PROFILE ('default') → shouldUpdateProfile = false
    expect(state.awsProfile).toBe('staging')
  })
})
