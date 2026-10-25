/**
 * Global scan state store using Zustand.
 *
 * Phase 4A additions:
 * - profiles: list of AWS CLI profile names discovered from local config
 * - profilesLoading / profilesError: loading state for profile discovery
 * - loadProfiles(): fetches GET /api/profiles
 * - verifiedFor: { profile, region } tuple that identity was verified against.
 *   Cleared whenever awsProfile or awsRegion changes, preventing stale identity.
 * - isIdentityCurrentlyValid: derived boolean — true only when verifiedFor
 *   matches the current profile and region exactly.
 *
 * Provenance is determined by ScanResult.simulated, not selectedMode.
 * Switching modes clears results to prevent stale data from appearing.
 */
import { create } from 'zustand'
import { ApiError, scanApi } from '../api/client'
import type { IdentityInfo, RegionInfo, ScanMode, ScanResult } from '../types/findings'

export type ScanStatus = 'idle' | 'scanning' | 'complete' | 'error'
export type IdentityStatus = 'idle' | 'checking' | 'verified' | 'error'
/** Phase 4E region selection mode. */
export type RegionMode = 'single' | 'multi' | 'all'

interface ScanState {
  // Scan result state
  status: ScanStatus
  scanResult: ScanResult | null
  error: string | null
  lastScanAt: string | null

  // Mode selection (UI preference only — provenance is in ScanResult.simulated)
  selectedMode: ScanMode

  // AWS profile discovery
  profiles: string[]
  profilesLoading: boolean
  profilesError: string | null

  // AWS region discovery
  regionList: RegionInfo[]
  regionsLoading: boolean
  regionsError: string | null
  /** true when ec2:DescribeRegions was called and succeeded */
  enabledRegionsAvailable: boolean

  // Live AWS identity state
  identityStatus: IdentityStatus
  identityInfo: IdentityInfo | null
  identityError: string | null
  /**
   * The structured error code from the backend (SESSION_EXPIRED, NO_CREDENTIALS,
   * NETWORK_ERROR, INSUFFICIENT_PERMISSIONS, etc.).
   * null when identityStatus is not 'error' or error came from a non-API source.
   */
  identityErrorCode: string | null

  /**
   * The (profile, region) pair that was successfully verified.
   * null if no verification has been done or verification was cleared.
   * Used to detect stale identity when profile or region changes.
   */
  verifiedFor: { profile: string; region: string } | null

  // Live scan configuration (never contains credential values)
  awsProfile: string
  awsRegion: string
  /** Phase 4E: region selection mode */
  regionMode: RegionMode
  /** Phase 4E: regions selected for multi-region scanning */
  selectedRegions: string[]
}

interface ScanActions {
  /** Switch between demo and live mode. Clears stale results immediately. */
  setMode: (mode: ScanMode) => void
  /** Set the AWS region for live scans. Clears identity if it was verified for a different region. */
  setAwsRegion: (region: string) => void
  /** Set the AWS profile for live scans. Clears identity if it was verified for a different profile. */
  setAwsProfile: (profile: string) => void
  /** Phase 4E: set the region selection mode (single/multi/all). */
  setRegionMode: (mode: RegionMode) => void
  /** Phase 4E: set the list of selected regions for multi-region scanning. */
  setSelectedRegions: (regions: string[]) => void
  /** Fetch available AWS CLI profiles from the backend. */
  loadProfiles: () => Promise<void>
  /** Fetch the list of AWS regions. Enriches with enabled status when a profile is provided. */
  loadRegions: (profile?: string) => Promise<void>
  /** Check AWS identity. Sets verifiedFor on success. */
  checkIdentity: () => Promise<void>
  /** Clear identity state (e.g. when switching away from live mode). */
  clearIdentity: () => void
  /** Trigger a scan in the currently selected mode. */
  triggerScan: (region?: string) => Promise<void>
  clearError: () => void
}

// Mirror the backend default — 'default' is the standard AWS SDK profile name.
// Users can override this by selecting a different profile from the dropdown.
// The actual default is determined by the backend's AWS_PROFILE env var.
const DEFAULT_AWS_PROFILE = 'default'
const DEFAULT_AWS_REGION = 'eu-north-1'

export const useScanStore = create<ScanState & ScanActions>((set, get) => ({
  // Scan result state
  status: 'idle',
  scanResult: null,
  error: null,
  lastScanAt: null,

  // Mode
  selectedMode: 'demo',

  // Profile discovery
  profiles: [],
  profilesLoading: false,
  profilesError: null,

  // Region discovery
  regionList: [],
  regionsLoading: false,
  regionsError: null,
  enabledRegionsAvailable: false,

  // Identity
  identityStatus: 'idle',
  identityInfo: null,
  identityError: null,
  identityErrorCode: null,
  verifiedFor: null,

  // Live config
  awsProfile: DEFAULT_AWS_PROFILE,
  awsRegion: DEFAULT_AWS_REGION,
  regionMode: 'single' as RegionMode,
  selectedRegions: [DEFAULT_AWS_REGION],

  setMode: (mode) => {
    const current = get().selectedMode
    if (mode === current) return
    // Clear scan results when switching modes to prevent stale provenance display
    // Demo Mode: clear all live-scan state. Never call /api/identity in demo mode.
    set({
      selectedMode: mode,
      scanResult: null,
      status: 'idle',
      error: null,
      lastScanAt: null,
      // Reset identity when leaving live mode (or entering demo)
      ...(mode === 'demo'
        ? {
            identityStatus: 'idle',
            identityInfo: null,
            identityError: null,
            identityErrorCode: null,
            verifiedFor: null,
          }
        : {}),
    })
  },

  setAwsRegion: (region) => {
    const { awsRegion } = get()
    if (region === awsRegion) return
    // Region change invalidates identity (verified for old region) and scan results
    // (EC2 findings are region-specific)
    set({
      awsRegion: region,
      identityStatus: 'idle',
      identityInfo: null,
      identityError: null,
      identityErrorCode: null,
      verifiedFor: null,
      // Scan results are region-specific — clear them on region change
      scanResult: null,
      status: 'idle',
      error: null,
      lastScanAt: null,
    })
  },

  setAwsProfile: (profile) => {
    const { awsProfile } = get()
    if (profile === awsProfile) return
    // Profile change always clears identity state — regardless of whether verifiedFor
    // is set. This handles the case where identityStatus is 'error' and verifiedFor
    // is null: the error belongs to the old profile and must not persist.
    // Also clear scan results — they belong to the old profile's session.
    set({
      awsProfile: profile,
      identityStatus: 'idle',
      identityInfo: null,
      identityError: null,
      identityErrorCode: null,
      verifiedFor: null,
      scanResult: null,
      status: 'idle',
      error: null,
      lastScanAt: null,
    })
  },

  setRegionMode: (mode) => {
    const { regionMode } = get()
    if (mode === regionMode) return
    // Clear scan results when region mode changes — results are mode-specific
    set({
      regionMode: mode,
      scanResult: null,
      status: 'idle',
      error: null,
      lastScanAt: null,
    })
  },

  setSelectedRegions: (regions) => {
    // Clear scan results when selected regions change
    set({
      selectedRegions: regions,
      scanResult: null,
      status: 'idle',
      error: null,
      lastScanAt: null,
    })
  },

  loadProfiles: async () => {
    set({ profilesLoading: true, profilesError: null })
    try {
      const response = await scanApi.listProfiles()
      if (response.discovery_error) {
        // Non-fatal: backend returned an error but still responded
        set({
          profiles: response.profiles,
          profilesLoading: false,
          profilesError: response.discovery_error,
        })
        return
      }
      // If there's a default profile from the env and it's not already the store default,
      // update the store to use it
      const defaultProfile = response.default_profile ?? DEFAULT_AWS_PROFILE
      const { awsProfile } = get()
      // Only update if it's the initial value (user hasn't manually changed it)
      const shouldUpdateProfile =
        awsProfile === DEFAULT_AWS_PROFILE &&
        defaultProfile !== DEFAULT_AWS_PROFILE &&
        response.profiles.includes(defaultProfile)
      set({
        profiles: response.profiles,
        profilesLoading: false,
        profilesError: null,
        ...(shouldUpdateProfile ? { awsProfile: defaultProfile } : {}),
      })
    } catch (err) {
      set({
        profiles: [],
        profilesLoading: false,
        profilesError:
          err instanceof ApiError
            ? err.message
            : 'Could not load AWS profiles. The backend may not be running.',
      })
    }
  },

  loadRegions: async (profile?: string) => {
    set({ regionsLoading: true, regionsError: null })
    try {
      const response = await scanApi.listRegions(profile)
      set({
        regionList: response.regions,
        regionsLoading: false,
        regionsError: response.describe_regions_error ?? null,
        enabledRegionsAvailable: response.enabled_regions_available,
        // If the current region isn't in the list, keep it — user may type a valid one
      })
    } catch (err) {
      set({
        regionList: [],
        regionsLoading: false,
        regionsError:
          err instanceof ApiError
            ? err.message
            : 'Could not load AWS regions. The backend may not be running.',
        enabledRegionsAvailable: false,
      })
    }
  },

  checkIdentity: async () => {
    const { awsProfile, awsRegion } = get()
    // Capture profile and region at call start for stale-response detection
    const profileAtStart = awsProfile
    const regionAtStart = awsRegion

    set({ identityStatus: 'checking', identityError: null, identityErrorCode: null, identityInfo: null, verifiedFor: null })
    try {
      const info = await scanApi.checkIdentity(awsProfile, awsRegion)
      // Stale-response guard: discard result if profile/region changed while in flight
      const current = get()
      if (current.awsProfile !== profileAtStart || current.awsRegion !== regionAtStart) {
        return
      }
      set({
        identityStatus: 'verified',
        identityInfo: info,
        identityError: null,
        identityErrorCode: null,
        verifiedFor: { profile: profileAtStart, region: regionAtStart },
      })
    } catch (err) {
      // Stale-response guard: discard error if profile/region changed while in flight
      const current = get()
      if (current.awsProfile !== profileAtStart || current.awsRegion !== regionAtStart) {
        return
      }
      const errorCode = err instanceof ApiError ? err.code : null
      const message =
        err instanceof ApiError
          ? err.message
          : 'Identity check failed. Verify the AWS profile is configured and SSO is active.'
      set({
        identityStatus: 'error',
        identityError: message,
        identityErrorCode: errorCode,
        identityInfo: null,
        verifiedFor: null,
      })
    }
  },

  clearIdentity: () =>
    set({
      identityStatus: 'idle',
      identityInfo: null,
      identityError: null,
      identityErrorCode: null,
      verifiedFor: null,
    }),

  triggerScan: async (regionOverride?: string) => {
    const { selectedMode, awsProfile, awsRegion, awsRegion: _awsRegion, verifiedFor,
            regionMode, selectedRegions } = get()
    const region = regionOverride ?? awsRegion

    // For live scans: verify identity is still valid for current profile/region
    if (selectedMode === 'live') {
      const isStillValid =
        verifiedFor !== null &&
        verifiedFor.profile === awsProfile &&
        verifiedFor.region === region
      if (!isStillValid) {
        set({
          status: 'error',
          error: 'AWS identity is no longer verified for the current profile and region. Please re-verify before scanning.',
        })
        return
      }
    }

    // Build the scan request — Phase 4E: pass regions when not in single mode
    let scanRequest: Parameters<typeof scanApi.triggerScan>[0]
    if (selectedMode === 'live') {
      if (regionMode === 'all') {
        scanRequest = { mode: 'live', regions: ['ALL_ENABLED'], aws_profile: awsProfile }
      } else if (regionMode === 'multi' && selectedRegions.length > 0) {
        scanRequest = { mode: 'live', regions: selectedRegions, aws_profile: awsProfile }
      } else {
        scanRequest = { mode: 'live', region, aws_profile: awsProfile }
      }
    } else {
      // Demo mode — pass region for single mode, regions for multi (demo exercises the path)
      if (regionMode === 'all') {
        scanRequest = { mode: 'demo', regions: ['ALL_ENABLED'] }
      } else if (regionMode === 'multi' && selectedRegions.length > 0) {
        scanRequest = { mode: 'demo', regions: selectedRegions }
      } else {
        scanRequest = { mode: 'demo', region }
      }
    }

    set({ status: 'scanning', error: null })
    try {
      const result = await scanApi.triggerScan(scanRequest)
      set({
        status: 'complete',
        scanResult: result,
        lastScanAt: new Date().toISOString(),
        error: null,
      })
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : 'An unexpected error occurred. Please try again.'
      // If the live scan fails with an auth error, clear the identity so the
      // user knows they need to re-verify before scanning again
      if (selectedMode === 'live' && err instanceof ApiError &&
          (err.code === 'INVALID_CREDENTIALS' || err.code === 'INSUFFICIENT_PERMISSIONS' ||
           err.code === 'SESSION_EXPIRED' || err.code === 'NO_CREDENTIALS')) {
        set({
          status: 'error',
          error: message,
          identityStatus: 'error',
          identityError: message,
          identityErrorCode: err.code,
          verifiedFor: null,
        })
      } else {
        set({ status: 'error', error: message })
      }
    }
  },

  clearError: () => {
    set((state) => ({
      error: null,
      status: state.status === 'error' ? 'idle' : state.status,
    }))
  },
}))

/**
 * Derived selector: true when identity is verified and the verification
 * matches the current awsProfile and awsRegion exactly.
 * Use this to gate the "Run Scan" button.
 */
export function selectIsIdentityCurrentlyValid(
  state: ScanState,
): boolean {
  const { identityStatus, verifiedFor, awsProfile, awsRegion } = state
  return (
    identityStatus === 'verified' &&
    verifiedFor !== null &&
    verifiedFor.profile === awsProfile &&
    verifiedFor.region === awsRegion
  )
}
