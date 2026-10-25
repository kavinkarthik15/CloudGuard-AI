/**
 * Phase 4D/4E frontend store tests.
 *
 * Covers:
 *   - Single region mode sends region (backward compat)
 *   - Multi-region mode sends regions array
 *   - All-enabled mode sends ['ALL_ENABLED']
 *   - Region mode change clears scanResult
 *   - setSelectedRegions clears scanResult
 *   - Profile switch clears region selection state
 *   - Demo Mode uses region mode but never calls /api/identity
 *   - ScanResult.coverage is passed through correctly
 *
 * Classification: MOCKED — all scanApi calls are vi.spyOn mocks.
 * No real AWS calls are made.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act } from 'react'
import { useScanStore } from '../../store/scanStore'
import type { ScanResult } from '../../types/findings'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockScanResult(simulated = true): ScanResult {
  return {
    scan_id: `scan-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    simulated,
    region: 'eu-north-1',
    findings: [],
    warnings: [],
    summary: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
    aws_account_id: null,
    aws_identity_arn: null,
    coverage: {
      requested_regions: ['eu-north-1'],
      scanned_regions: ['eu-north-1'],
      failed_regions: [],
      s3_buckets_requested: 5,
      s3_buckets_scanned: 5,
      s3_buckets_failed: 0,
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
// Region mode switching
// ---------------------------------------------------------------------------

describe('setRegionMode', () => {
  it('clears scan result when mode changes', () => {
    act(() => {
      useScanStore.setState({
        regionMode: 'single',
        scanResult: mockScanResult(),
        status: 'complete',
      })
    })

    act(() => useScanStore.getState().setRegionMode('multi'))

    const state = useScanStore.getState()
    expect(state.regionMode).toBe('multi')
    expect(state.scanResult).toBeNull()
    expect(state.status).toBe('idle')
  })

  it('is a no-op when setting the same mode', () => {
    act(() => {
      useScanStore.setState({
        regionMode: 'single',
        scanResult: mockScanResult(),
        status: 'complete',
      })
    })

    act(() => useScanStore.getState().setRegionMode('single'))

    // No change
    expect(useScanStore.getState().scanResult).not.toBeNull()
    expect(useScanStore.getState().status).toBe('complete')
  })

  it('clears scan result when switching to all mode', () => {
    act(() => {
      useScanStore.setState({
        regionMode: 'single',
        scanResult: mockScanResult(),
        status: 'complete',
      })
    })

    act(() => useScanStore.getState().setRegionMode('all'))

    expect(useScanStore.getState().scanResult).toBeNull()
  })
})

describe('setSelectedRegions', () => {
  it('clears scan result when selected regions change', () => {
    act(() => {
      useScanStore.setState({
        selectedRegions: ['eu-north-1'],
        scanResult: mockScanResult(),
        status: 'complete',
      })
    })

    act(() => useScanStore.getState().setSelectedRegions(['eu-north-1', 'us-east-1']))

    const state = useScanStore.getState()
    expect(state.selectedRegions).toEqual(['eu-north-1', 'us-east-1'])
    expect(state.scanResult).toBeNull()
    expect(state.status).toBe('idle')
  })
})

// ---------------------------------------------------------------------------
// triggerScan region mode routing
// ---------------------------------------------------------------------------

describe('triggerScan — region mode routing', () => {
  it('single region mode sends region (not regions array)', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockScanResult(true))

    act(() => {
      useScanStore.setState({
        selectedMode: 'demo',
        awsRegion: 'eu-north-1',
        regionMode: 'single',
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    expect(scanApi.triggerScan).toHaveBeenCalledWith(
      expect.objectContaining({ mode: 'demo', region: 'eu-north-1' })
    )
    // Must NOT have a regions array in single mode
    const callArg = (scanApi.triggerScan as ReturnType<typeof vi.fn>).mock.calls[0][0]
    expect(callArg.regions).toBeUndefined()
  })

  it('multi-region mode sends regions array', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockScanResult(true))

    act(() => {
      useScanStore.setState({
        selectedMode: 'demo',
        regionMode: 'multi',
        selectedRegions: ['eu-north-1', 'us-east-1'],
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    const callArg = (scanApi.triggerScan as ReturnType<typeof vi.fn>).mock.calls[0][0]
    expect(callArg.regions).toEqual(['eu-north-1', 'us-east-1'])
  })

  it('all-enabled mode sends ["ALL_ENABLED"] sentinel', async () => {
    const { scanApi } = await import('../../api/client')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockScanResult(true))

    act(() => {
      useScanStore.setState({
        selectedMode: 'demo',
        regionMode: 'all',
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    const callArg = (scanApi.triggerScan as ReturnType<typeof vi.fn>).mock.calls[0][0]
    expect(callArg.regions).toEqual(['ALL_ENABLED'])
  })
})

// ---------------------------------------------------------------------------
// ScanResult.coverage pass-through
// ---------------------------------------------------------------------------

describe('ScanResult.coverage', () => {
  it('stores coverage metadata from scan result', async () => {
    const { scanApi } = await import('../../api/client')
    const resultWithCoverage = mockScanResult(true)
    resultWithCoverage.coverage!.scanned_regions = ['eu-north-1', 'us-east-1']
    resultWithCoverage.coverage!.failed_regions = ['ap-east-1']

    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(resultWithCoverage)

    act(() => {
      useScanStore.setState({ selectedMode: 'demo', regionMode: 'single' })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    const { scanResult } = useScanStore.getState()
    expect(scanResult?.coverage?.scanned_regions).toEqual(['eu-north-1', 'us-east-1'])
    expect(scanResult?.coverage?.failed_regions).toEqual(['ap-east-1'])
  })
})

// ---------------------------------------------------------------------------
// Profile switch still clears region-related state
// ---------------------------------------------------------------------------

describe('setAwsProfile with region mode', () => {
  it('profile switch clears scan result regardless of region mode', () => {
    act(() => {
      useScanStore.setState({
        awsProfile: 'profile-a',
        regionMode: 'multi',
        selectedRegions: ['eu-north-1', 'us-east-1'],
        scanResult: mockScanResult(false),
        status: 'complete',
        identityStatus: 'verified',
        verifiedFor: { profile: 'profile-a', region: 'eu-north-1' },
      })
    })

    act(() => useScanStore.getState().setAwsProfile('profile-b'))

    const state = useScanStore.getState()
    expect(state.scanResult).toBeNull()
    expect(state.identityStatus).toBe('idle')
    // selectedRegions and regionMode are preserved on profile switch
    expect(state.regionMode).toBe('multi')
    expect(state.selectedRegions).toEqual(['eu-north-1', 'us-east-1'])
  })
})

// ---------------------------------------------------------------------------
// Demo Mode regression
// ---------------------------------------------------------------------------

describe('Demo Mode regression', () => {
  it('demo mode ignores identity state with multi-region selection', async () => {
    const { scanApi } = await import('../../api/client')
    const checkIdentitySpy = vi.spyOn(scanApi, 'checkIdentity')
    vi.spyOn(scanApi, 'triggerScan').mockResolvedValueOnce(mockScanResult(true))

    act(() => {
      useScanStore.setState({
        selectedMode: 'demo',
        regionMode: 'multi',
        selectedRegions: ['eu-north-1', 'us-east-1'],
        identityStatus: 'idle',
        verifiedFor: null,
      })
    })

    await act(async () => { await useScanStore.getState().triggerScan() })

    expect(checkIdentitySpy).not.toHaveBeenCalled()
    expect(useScanStore.getState().scanResult?.simulated).toBe(true)
  })
})
