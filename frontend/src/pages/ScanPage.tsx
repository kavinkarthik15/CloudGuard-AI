import { useEffect } from 'react'
import { ErrorBanner } from '../components/shared/ErrorBanner'
import { LoadingSpinner } from '../components/shared/LoadingSpinner'
import { useScanStore, selectIsIdentityCurrentlyValid } from '../store/scanStore'
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
// Sub-component: profile selector
// ---------------------------------------------------------------------------

function ProfileSelector() {
  const {
    awsProfile, awsRegion,
    profiles, profilesLoading, profilesError,
    setAwsProfile, setAwsRegion,
    loadProfiles,
    identityStatus, verifiedFor, clearIdentity,
    status,
  } = useScanStore()

  const isBusy = status === 'scanning' || identityStatus === 'checking'

  // Show a stale-identity warning when region or profile diverges from verifiedFor
  const isStale =
    verifiedFor !== null &&
    (verifiedFor.profile !== awsProfile || verifiedFor.region !== awsRegion)

  return (
    <div className="space-y-4">
      {/* AWS Region input */}
      <div>
        <label htmlFor="aws-region" className="block text-sm text-slate-400 mb-1.5">
          AWS Region
        </label>
        <input
          id="aws-region"
          type="text"
          value={awsRegion}
          onChange={(e) => setAwsRegion(e.target.value)}
          placeholder="eu-north-1"
          className="input max-w-xs"
          disabled={isBusy}
          aria-label="AWS Region"
        />
      </div>

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
    identityStatus, identityInfo, identityError,
    awsProfile,
    checkIdentity,
    status,
  } = useScanStore()
  const isIdentityValid = selectIsIdentityCurrentlyValid(useScanStore.getState())

  const isBusy = status === 'scanning' || identityStatus === 'checking'

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

      {/* Identity error */}
      {identityStatus === 'error' && identityError && (
        <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-4">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-red-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
            </svg>
            <div>
              <p className="text-sm font-semibold text-red-300">Authentication Failed</p>
              <p className="mt-1 text-sm text-red-400/80">{identityError}</p>
              <p className="mt-2 text-xs text-red-400/60">
                Run <code className="font-mono">aws sso login --profile {awsProfile}</code> then try again.
              </p>
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

            {/* Profile and region configuration */}
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
                  {scanResult.warnings.length} resource{scanResult.warnings.length !== 1 ? 's' : ''} could not be fully assessed.
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
