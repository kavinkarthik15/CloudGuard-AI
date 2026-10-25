import { useEffect } from 'react'
import { ErrorBanner } from '../components/shared/ErrorBanner'
import { LoadingSpinner } from '../components/shared/LoadingSpinner'
import { useScanStore, selectIsIdentityCurrentlyValid } from '../store/scanStore'
import type { RegionMode as _RegionModeType } from '../store/scanStore'
import type { ScanMode } from '../types/findings'

function formatTimestamp(iso: string | null): string {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  } catch {
    return iso
  }
}

// ---------------------------------------------------------------------------
// Sub-component: mode selector tabs
// ---------------------------------------------------------------------------

interface ModeSelectorProps {
  selected: ScanMode
  onChange: (mode: ScanMode) => void
  disabled: boolean
}

function ModeSelector({ selected, onChange, disabled }: ModeSelectorProps) {
  return (
    <div
      role="tablist"
      aria-label="Scan mode"
      className="flex rounded-lg overflow-hidden border border-navy-600 w-fit"
    >
      {(['demo', 'live'] as ScanMode[]).map((mode) => {
        const isActive = selected === mode
        return (
          <button
            key={mode}
            role="tab"
            aria-selected={isActive}
            onClick={() => !disabled && onChange(mode)}
            disabled={disabled}
            className={`px-5 py-2 text-sm font-medium transition-colors focus-visible:ring-2 focus-visible:ring-aws-500 ${
              isActive
                ? mode === 'demo'
                  ? 'bg-amber-500/15 text-amber-300 border-r border-navy-600'
                  : 'bg-green-900/30 text-green-300'
                : 'bg-navy-900 text-slate-400 hover:text-slate-200 border-r border-navy-600 last:border-r-0'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {mode === 'demo' ? '⬡ Demo Mode' : '⬡ Live AWS'}
          </button>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sub-component: Phase 4E region mode selector
// ---------------------------------------------------------------------------

function RegionModeSelector() {
  const {
    regionMode, selectedRegions, awsRegion,
    setRegionMode, setSelectedRegions, setAwsRegion,
    regionList, enabledRegionsAvailable,
    status, identityStatus,
  } = useScanStore()

  const isBusy = status === 'scanning' || identityStatus === 'checking'

  const modes: { value: _RegionModeType; label: string; desc: string }[] = [
    { value: 'single', label: 'Single Region', desc: 'Scan one region' },
    { value: 'multi', label: 'Multiple Regions', desc: 'Select specific regions' },
    { value: 'all', label: 'All Enabled', desc: 'All regions enabled in this account' },
  ]

  return (
    <div className="space-y-3">
      <div>
        <p className="text-sm text-slate-400 mb-2">Region Selection</p>
        <div role="radiogroup" aria-label="Region selection mode" className="flex gap-2 flex-wrap">
          {modes.map((m) => (
            <button
              key={m.value}
              role="radio"
              aria-checked={regionMode === m.value}
              onClick={() => !isBusy && setRegionMode(m.value)}
              disabled={isBusy}
              className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                regionMode === m.value
                  ? 'bg-aws-500/20 border-aws-500/50 text-aws-300'
                  : 'bg-navy-900 border-navy-600 text-slate-400 hover:text-slate-200'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>
      </div>

      {regionMode === 'single' && (
        <div>
          <label htmlFor="aws-region-single" className="block text-sm text-slate-400 mb-1.5">
            AWS Region
          </label>
          <input
            id="aws-region-single"
            type="text"
            value={awsRegion}
            onChange={(e) => setAwsRegion(e.target.value)}
            placeholder="eu-north-1"
            className="input max-w-xs"
            disabled={isBusy}
          />
        </div>
      )}

      {regionMode === 'multi' && (
        <div>
          <p className="text-sm text-slate-400 mb-1.5">
            Select regions to scan
            {!enabledRegionsAvailable && (
              <span className="ml-2 text-xs text-slate-500">(verify identity to see enabled status)</span>
            )}
          </p>
          {regionList.length > 0 ? (
            <div className="max-h-40 overflow-y-auto border border-navy-600 rounded-lg divide-y divide-navy-700">
              {regionList.map((r) => {
                const checked = selectedRegions.includes(r.name)
                return (
                  <label
                    key={r.name}
                    className={`flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-navy-800/50 ${
                      isBusy ? 'opacity-50 pointer-events-none' : ''
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedRegions([...selectedRegions, r.name])
                        } else {
                          setSelectedRegions(selectedRegions.filter((x) => x !== r.name))
                        }
                      }}
                      className="rounded border-navy-500"
                    />
                    <span className="font-mono text-xs text-slate-300">{r.name}</span>
                    <span className="text-xs text-slate-500 flex-1">{r.description}</span>
                    {r.enabled === true && (
                      <span className="text-xs text-green-400">enabled</span>
                    )}
                    {r.enabled === false && (
                      <span className="text-xs text-slate-600">opt-in</span>
                    )}
                  </label>
                )
              })}
            </div>
          ) : (
            <p className="text-xs text-slate-500">
              No region list available. Load regions or enter manually below.
            </p>
          )}
          {selectedRegions.length === 0 && (
            <p className="mt-1 text-xs text-yellow-400">Select at least one region.</p>
          )}
          {selectedRegions.length > 0 && (
            <p className="mt-1 text-xs text-slate-500">
              {selectedRegions.length} region{selectedRegions.length !== 1 ? 's' : ''} selected
            </p>
          )}
        </div>
      )}

      {regionMode === 'all' && (
        <div className="rounded-lg border border-blue-500/20 bg-blue-950/10 px-3 py-2">
          <p className="text-xs text-blue-300">
            CloudGuard AI will call <code className="font-mono text-xs bg-navy-900/50 rounded px-1">ec2:DescribeRegions</code> to
            discover all regions enabled for this account and scan security groups in each.
            {!enabledRegionsAvailable && (
              <span className="block mt-1 text-blue-400/70">
                If region discovery is not permitted, falls back to all known regions from the AWS SDK.
              </span>
            )}
          </p>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sub-component: profile selector
// ---------------------------------------------------------------------------

function ProfileSelector() {
  const {
    awsProfile,
    profiles, profilesLoading, profilesError,
    setAwsProfile,
    loadProfiles,
    identityStatus, verifiedFor, clearIdentity,
    status,
    awsRegion,
  } = useScanStore()

  const isBusy = status === 'scanning' || identityStatus === 'checking'

  // Show a stale-identity warning when region or profile diverges from verifiedFor
  const isStale =
    verifiedFor !== null &&
    (verifiedFor.profile !== awsProfile || verifiedFor.region !== awsRegion)

  return (
    <div className="space-y-4">
      {/* AWS CLI Profile selector */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label htmlFor="aws-profile" className="block text-sm text-slate-400">
            AWS CLI Profile
          </label>
          <button
            type="button"
            onClick={() => loadProfiles()}
            disabled={isBusy || profilesLoading}
            aria-label="Refresh AWS profiles"
            className="btn-ghost text-xs py-1 px-2"
            title="Refresh profile list from local AWS configuration"
          >
            {profilesLoading ? (
              <LoadingSpinner size="sm" label="Loading profiles…" />
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Refresh
              </>
            )}
          </button>
        </div>

        {/* Show dropdown when profiles are available, text input as fallback */}
        {profiles.length > 0 ? (
          <select
            id="aws-profile"
            value={awsProfile}
            onChange={(e) => {
              setAwsProfile(e.target.value)
              if (identityStatus === 'verified') clearIdentity()
            }}
            disabled={isBusy}
            aria-label="AWS CLI Profile"
            className="input max-w-xs bg-navy-900"
          >
            {profiles.map((p) => (
              <option key={p} value={p} className="bg-navy-900 text-slate-100">
                {p}
              </option>
            ))}
            {/* Allow entering a profile not in the list */}
            {!profiles.includes(awsProfile) && awsProfile && (
              <option value={awsProfile} className="bg-navy-900 text-slate-100">
                {awsProfile} (custom)
              </option>
            )}
          </select>
        ) : (
          <input
            id="aws-profile"
            type="text"
            value={awsProfile}
            onChange={(e) => {
              setAwsProfile(e.target.value)
              if (identityStatus === 'verified') clearIdentity()
            }}
            placeholder="default"
            className="input max-w-xs"
            disabled={isBusy}
            aria-label="AWS CLI Profile"
          />
        )}

        {/* Profile discovery error */}
        {profilesError && (
          <p className="mt-1 text-xs text-yellow-400">
            ⚠ Could not load profiles: {profilesError}. Enter a profile name manually.
          </p>
        )}

        <p className="mt-1 text-xs text-slate-600">
          Credentials are resolved via the Boto3 credential chain — never entered here.
          Run <code className="font-mono text-slate-500">aws sso login --profile {awsProfile || 'default'}</code> to authenticate.
        </p>
      </div>

      {/* Stale identity warning */}
      {isStale && (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-950/20 px-4 py-3">
          <p className="text-xs text-yellow-300 flex items-center gap-2">
            <svg className="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
              <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
            </svg>
            Profile or region changed — re-verify identity before scanning.
          </p>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sub-component: identity verification panel
// ---------------------------------------------------------------------------

function IdentityVerificationPanel() {
  const {
    identityStatus, identityInfo, identityError, identityErrorCode,
    awsProfile,
    checkIdentity,
    status,
  } = useScanStore()
  const isIdentityValid = selectIsIdentityCurrentlyValid(useScanStore.getState())

  const isBusy = status === 'scanning' || identityStatus === 'checking'

  // Render an actionable error message based on the structured error code
  function renderIdentityError() {
    if (!identityError) return null
    const codeStyle = 'font-mono text-xs bg-navy-900/50 rounded px-1 py-0.5'
    switch (identityErrorCode) {
      case 'SESSION_EXPIRED':
        return (
          <>
            <p className="text-sm font-semibold text-red-300">Authentication Failed — SSO Session Expired</p>
            <p className="mt-1 text-sm text-red-400/80">Your AWS SSO session has expired.</p>
            <p className="mt-2 text-xs text-red-400/60">
              Run <code className={codeStyle}>aws sso login --profile {awsProfile}</code> then try again.
            </p>
          </>
        )
      case 'NO_CREDENTIALS':
        return (
          <>
            <p className="text-sm font-semibold text-red-300">No Credentials Found</p>
            <p className="mt-1 text-sm text-red-400/80">
              Profile <code className={codeStyle}>{awsProfile}</code> has no credentials configured.
            </p>
            <p className="mt-2 text-xs text-red-400/60">
              Run <code className={codeStyle}>aws configure --profile {awsProfile}</code> or{' '}
              <code className={codeStyle}>aws sso login --profile {awsProfile}</code> then try again.
            </p>
          </>
        )
      case 'NETWORK_ERROR':
        return (
          <>
            <p className="text-sm font-semibold text-red-300">Cannot Reach AWS</p>
            <p className="mt-1 text-sm text-red-400/80">
              Could not connect to AWS. Check your internet connection and try again.
            </p>
          </>
        )
      case 'INVALID_PROFILE':
        return (
          <>
            <p className="text-sm font-semibold text-red-300">Invalid Profile Name</p>
            <p className="mt-1 text-sm text-red-400/80">
              Profile <code className={codeStyle}>{awsProfile}</code> contains invalid characters
              and cannot be used. Select a valid AWS CLI profile from the dropdown.
            </p>
          </>
        )
      case 'INSUFFICIENT_PERMISSIONS':
        return (
          <>
            <p className="text-sm font-semibold text-red-300">Permission Denied</p>
            <p className="mt-1 text-sm text-red-400/80">
              Profile <code className={codeStyle}>{awsProfile}</code> does not have{' '}
              <code className={codeStyle}>sts:GetCallerIdentity</code> permission. Check IAM permissions.
            </p>
          </>
        )
      default:
        // Forward-compatible fallback for any future error codes
        return (
          <>
            <p className="text-sm font-semibold text-red-300">Authentication Failed</p>
            <p className="mt-1 text-sm text-red-400/80">{identityError}</p>
            <p className="mt-2 text-xs text-red-400/60">
              Run <code className={codeStyle}>aws sso login --profile {awsProfile}</code> then try again.
            </p>
          </>
        )
    }
  }

  return (
    <div className="space-y-3">
      {/* Verify button — hidden when already verified for current settings */}
      {!isIdentityValid && (
        <button
          onClick={checkIdentity}
          disabled={isBusy}
          className="btn-secondary"
          aria-label="Verify AWS identity"
        >
          {identityStatus === 'checking' ? (
            <>
              <LoadingSpinner size="sm" label="" />
              Verifying identity…
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Verify AWS Identity
            </>
          )}
        </button>
      )}

      {/* Identity error — rendered with per-code actionable messages */}
      {identityStatus === 'error' && identityError && (
        <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-4">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-red-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
            </svg>
            <div>
              {renderIdentityError()}
            </div>
          </div>
        </div>
      )}

      {/* Verified identity card */}
      {isIdentityValid && identityInfo && (
        <div className="rounded-lg border border-green-500/30 bg-green-950/15 p-4">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-green-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
            </svg>
            <div>
              <p className="text-sm font-semibold text-green-300">Identity Verified</p>
              <dl className="mt-2 space-y-1 text-xs">
                <div className="flex gap-2">
                  <dt className="text-slate-500 w-20 shrink-0">Account</dt>
                  <dd className="font-mono text-slate-300">{identityInfo.account_id}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-slate-500 w-20 shrink-0">Role</dt>
                  <dd className="font-mono text-slate-300 break-all">
                    {identityInfo.arn.split('/').slice(-2).join('/')}
                  </dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-slate-500 w-20 shrink-0">Region</dt>
                  <dd className="font-mono text-slate-300">{identityInfo.region}</dd>
                </div>
              </dl>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main ScanPage
// ---------------------------------------------------------------------------

export function ScanPage() {
  const {
    status, scanResult, error, lastScanAt,
    selectedMode,
    awsRegion,
    triggerScan, clearError, setMode,
    loadProfiles,
  } = useScanStore()

  // Load profiles when switching to Live mode
  useEffect(() => {
    if (selectedMode === 'live') {
      loadProfiles()
    }
  }, [selectedMode]) // eslint-disable-line react-hooks/exhaustive-deps

  const isIdentityValid = selectIsIdentityCurrentlyValid(useScanStore.getState())
  const totalFindings = scanResult?.findings.length ?? 0
  const isLiveResult = scanResult !== null && !scanResult.simulated
  const canScanLive = selectedMode === 'live' && isIdentityValid
  const isBusy = status === 'scanning'

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Security Scan</h1>
        <p className="mt-1 text-slate-500 text-sm">
          Evaluate AWS resource configurations for security misconfigurations.
        </p>
      </div>

      {/* Mode selector */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <h2 className="text-sm font-semibold text-slate-300">Scan Mode</h2>
          <ModeSelector
            selected={selectedMode}
            onChange={setMode}
            disabled={isBusy}
          />
        </div>

        {selectedMode === 'demo' ? (
          /* Demo mode info */
          <div className="rounded-lg border border-amber-500/20 bg-amber-950/10 p-4">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
              </svg>
              <div>
                <p className="text-sm font-semibold text-amber-300">Demo Mode — Simulated Data</p>
                <p className="mt-1 text-sm text-amber-400/80 leading-relaxed">
                  Findings are generated from JSON fixture configurations — no real AWS API calls
                  are made. Use Live AWS mode to scan a real account.
                </p>
              </div>
            </div>
          </div>
        ) : (
          /* Live mode: profile selector + identity panel */
          <div className="space-y-4">
            <div className="rounded-lg border border-blue-500/20 bg-blue-950/10 p-4">
              <div className="flex items-start gap-3">
                <svg className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
                <div>
                  <p className="text-sm font-semibold text-blue-300">Live AWS Scanning — Read-Only</p>
                  <p className="mt-1 text-sm text-blue-400/80 leading-relaxed">
                    CloudGuard AI uses read-only AWS permissions only (<code className="font-mono text-xs">s3:List*</code>, <code className="font-mono text-xs">s3:Get*</code>, <code className="font-mono text-xs">ec2:Describe*</code>).
                    No resources will be created or modified. Credentials are resolved via the
                    standard Boto3 credential chain — never entered in this interface.
                  </p>
                </div>
              </div>
            </div>

            {/* Phase 4E: Region selection */}
            <RegionModeSelector />

            {/* Profile and identity configuration */}
            <ProfileSelector />

            {/* Identity verification */}
            <IdentityVerificationPanel />
          </div>
        )}
      </div>

      {/* Scan controls */}
      <div className="card space-y-4">
        <h2 className="text-sm font-semibold text-slate-300">
          {selectedMode === 'demo' ? 'Run Demo Scan' : 'Run Live AWS Scan'}
        </h2>

        {selectedMode === 'live' && !isIdentityValid && (
          <p className="text-xs text-slate-500">
            Verify your AWS identity above before running a live scan.
          </p>
        )}

        <button
          onClick={() => triggerScan()}
          disabled={isBusy || (selectedMode === 'live' && !canScanLive)}
          aria-disabled={isBusy || (selectedMode === 'live' && !canScanLive)}
          className="btn-primary"
        >
          {status === 'scanning' ? (
            <>
              <LoadingSpinner size="sm" label="" />
              {selectedMode === 'demo' ? 'Scanning fixtures…' : 'Scanning AWS…'}
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              Run Scan
            </>
          )}
        </button>
      </div>

      {/* Error state */}
      {status === 'error' && error && (
        <ErrorBanner message={error} onDismiss={clearError} />
      )}

      {/* Completion state */}
      {status === 'complete' && scanResult && (
        <div className={`card border ${isLiveResult ? 'border-green-500/20 bg-green-950/10' : 'border-amber-500/20 bg-amber-950/10'}`}>
          <div className="flex items-start gap-3">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${isLiveResult ? 'bg-green-900/40' : 'bg-amber-900/40'}`}>
              <svg className={`w-5 h-5 ${isLiveResult ? 'text-green-400' : 'text-amber-400'}`} fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            </div>
            <div>
              <p className={`text-sm font-semibold ${isLiveResult ? 'text-green-300' : 'text-amber-300'}`}>
                Scan completed — {isLiveResult ? 'Live AWS data' : 'Simulated data'}
              </p>
              <p className={`mt-1 text-sm ${isLiveResult ? 'text-green-400/80' : 'text-amber-400/80'}`}>
                <strong className={isLiveResult ? 'text-green-300' : 'text-amber-300'}>{totalFindings} findings</strong>
                {' '}identified
                {lastScanAt && <> at {formatTimestamp(lastScanAt)}</>}.
                {isLiveResult && scanResult.aws_account_id && (
                  <> Account <span className="font-mono">{scanResult.aws_account_id}</span>, region <span className="font-mono">{scanResult.region}</span>.</>
                )}
              </p>
              {totalFindings === 0 && isLiveResult && (
                <p className="mt-1.5 text-xs text-slate-400">
                  Zero findings does not guarantee a secure configuration — it means no
                  misconfigurations matching the current rules were detected in the scanned resources.
                </p>
              )}
              {scanResult.warnings.length > 0 && (
                <p className="mt-1 text-xs text-yellow-400">
                  ⚠ {scanResult.warnings.length} resource{scanResult.warnings.length !== 1 ? 's' : ''} could not be fully assessed.{' '}
                  {scanResult.coverage?.failed_regions && scanResult.coverage.failed_regions.length > 0 && (
                    <span>Regions with errors: {scanResult.coverage.failed_regions.join(', ')}.</span>
                  )}
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Severity breakdown */}
      {status === 'complete' && scanResult && (
        <div className="card">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Findings by Severity</h2>
          {totalFindings === 0 ? (
            <p className="text-sm text-slate-500">No findings detected in this scan.</p>
          ) : (
            <div className="space-y-2">
              {Object.entries(scanResult.summary)
                .filter(([, count]) => count > 0)
                .map(([severity, count]) => (
                  <div key={severity} className="flex items-center justify-between text-sm">
                    <span className="text-slate-400">{severity}</span>
                    <span className="font-mono font-semibold text-slate-200">{count}</span>
                  </div>
                ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
