import { useEffect, useRef, useState } from 'react'
import { ErrorBanner } from '../components/shared/ErrorBanner'
import { LoadingSpinner } from '../components/shared/LoadingSpinner'
import { useScanStore, selectIsIdentityCurrentlyValid } from '../store/scanStore'
import type { RegionMode as _RegionModeType } from '../store/scanStore'
import type { ScanMode } from '../types/findings'
import { CoveragePanel } from './DashboardPage'

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
  /** When false, the Live AWS tab is hidden/disabled (production demo-only mode). */
  liveModeAvailable: boolean
}

function ModeSelector({ selected, onChange, disabled, liveModeAvailable }: ModeSelectorProps) {
  return (
    <div
      role="tablist"
      aria-label="Scan mode"
      className="flex rounded-lg overflow-hidden border border-navy-600 w-fit"
    >
      {(['demo', 'live'] as ScanMode[]).map((mode) => {
        const isActive = selected === mode
        const isLiveUnavailable = mode === 'live' && !liveModeAvailable
        return (
          <button
            key={mode}
            role="tab"
            aria-selected={isActive}
            onClick={() => !disabled && !isLiveUnavailable && onChange(mode)}
            disabled={disabled || isLiveUnavailable}
            title={isLiveUnavailable ? 'Live AWS scanning is disabled in this deployment.' : undefined}
            className={`px-5 py-2 text-sm font-medium transition-colors focus-visible:ring-2 focus-visible:ring-aws-500 ${
              isActive
                ? mode === 'demo'
                  ? 'bg-amber-500/15 text-amber-300 border-r border-navy-600'
                  : 'bg-green-900/30 text-green-300'
                : isLiveUnavailable
                  ? 'bg-navy-900 text-slate-600 border-r border-navy-600 last:border-r-0 cursor-not-allowed'
                  : 'bg-navy-900 text-slate-400 hover:text-slate-200 border-r border-navy-600 last:border-r-0'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {mode === 'demo' ? '⬡ Demo Mode' : '⬡ Live AWS'}
            {isLiveUnavailable && (
              <span className="ml-1.5 text-xs text-slate-600">(disabled)</span>
            )}
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
// Sub-component: credential form (replaces profile selector for local testing)
// ---------------------------------------------------------------------------

interface ExplicitCreds {
  accessKeyId: string
  secretAccessKey: string
  sessionToken: string
}

interface CredentialFormProps {
  creds: ExplicitCreds
  onChange: (creds: ExplicitCreds) => void
  disabled: boolean
}

function CredentialForm({ creds, onChange, disabled }: CredentialFormProps) {
  const [showSecret, setShowSecret] = useState(false)
  const [showToken, setShowToken] = useState(false)

  const keyIdValid = creds.accessKeyId.trim().length === 0 ||
    /^(AKIA|ASIA)[A-Z0-9]{16}$/.test(creds.accessKeyId.trim())

  return (
    <div className="space-y-4">
      {/* Security notice */}
      <div className="rounded-lg border border-amber-500/20 bg-amber-950/10 px-4 py-3 text-xs text-amber-300/80">
        <strong className="text-amber-300">Local testing only.</strong>{' '}
        Credentials are sent to the local backend only, used for this scan only, and never stored.
        Use a dedicated IAM identity with the minimum read-only permissions listed in{' '}
        <code className="font-mono">docs/iam-policy.json</code>.
        AWS IAM policies enforce read-only access — this form does not.
      </div>

      {/* Access Key ID */}
      <div>
        <label htmlFor="aws-key-id" className="block text-sm text-slate-400 mb-1.5">
          AWS Access Key ID <span className="text-red-400">*</span>
        </label>
        <input
          id="aws-key-id"
          type="text"
          value={creds.accessKeyId}
          onChange={(e) => onChange({ ...creds, accessKeyId: e.target.value })}
          placeholder="AKIA… or ASIA…"
          className="input max-w-xs font-mono text-sm"
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
          aria-describedby="key-id-hint"
        />
        {creds.accessKeyId && !keyIdValid && (
          <p id="key-id-hint" className="mt-1 text-xs text-red-400">
            Access Key ID must start with AKIA or ASIA and be 20 characters.
          </p>
        )}
      </div>

      {/* Secret Access Key */}
      <div>
        <label htmlFor="aws-secret" className="block text-sm text-slate-400 mb-1.5">
          AWS Secret Access Key <span className="text-red-400">*</span>
        </label>
        <div className="flex items-center gap-2 max-w-xs">
          <input
            id="aws-secret"
            type={showSecret ? 'text' : 'password'}
            value={creds.secretAccessKey}
            onChange={(e) => onChange({ ...creds, secretAccessKey: e.target.value })}
            placeholder="Secret key"
            className="input flex-1 font-mono text-sm"
            disabled={disabled}
            autoComplete="new-password"
            spellCheck={false}
          />
          <button
            type="button"
            onClick={() => setShowSecret((v) => !v)}
            disabled={disabled}
            className="btn-ghost text-xs py-2 px-2 shrink-0"
            aria-label={showSecret ? 'Hide secret key' : 'Show secret key'}
          >
            {showSecret ? '🙈' : '👁'}
          </button>
        </div>
      </div>

      {/* Session Token (optional) */}
      <div>
        <label htmlFor="aws-token" className="block text-sm text-slate-400 mb-1.5">
          AWS Session Token <span className="text-slate-600">(optional — required for temporary credentials)</span>
        </label>
        <div className="flex items-center gap-2 max-w-sm">
          <input
            id="aws-token"
            type={showToken ? 'text' : 'password'}
            value={creds.sessionToken}
            onChange={(e) => onChange({ ...creds, sessionToken: e.target.value })}
            placeholder="Session token (if using STS / SSO temporary credentials)"
            className="input flex-1 font-mono text-sm"
            disabled={disabled}
            autoComplete="new-password"
            spellCheck={false}
          />
          <button
            type="button"
            onClick={() => setShowToken((v) => !v)}
            disabled={disabled}
            className="btn-ghost text-xs py-2 px-2 shrink-0"
            aria-label={showToken ? 'Hide session token' : 'Show session token'}
          >
            {showToken ? '🙈' : '👁'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sub-component: identity verification panel (credential-aware)
// ---------------------------------------------------------------------------

function IdentityVerificationPanel({ creds }: { creds: ExplicitCreds }) {
  const {
    identityStatus, identityInfo, identityError, identityErrorCode,
    checkIdentity,
    status,
  } = useScanStore()
  const isIdentityValid = selectIsIdentityCurrentlyValid(useScanStore.getState())

  const isBusy = status === 'scanning' || identityStatus === 'checking'

  const hasExplicitCreds = creds.accessKeyId.trim() !== '' && creds.secretAccessKey.trim() !== ''

  function handleVerify() {
    if (hasExplicitCreds) {
      checkIdentity({
        accessKeyId: creds.accessKeyId.trim(),
        secretAccessKey: creds.secretAccessKey.trim(),
        sessionToken: creds.sessionToken.trim() || undefined,
      })
    } else {
      checkIdentity()
    }
  }

  function renderIdentityError() {
    if (!identityError) return null
    const codeStyle = 'font-mono text-xs bg-navy-900/50 rounded px-1 py-0.5'
    switch (identityErrorCode) {
      case 'INSUFFICIENT_PERMISSIONS':
        return (
          <>
            <p className="text-sm font-semibold text-red-300">Permission Denied</p>
            <p className="mt-1 text-sm text-red-400/80">
              <code className={codeStyle}>sts:GetCallerIdentity</code> was denied.
              Ensure the IAM identity has the required read-only permissions from{' '}
              <code className={codeStyle}>docs/iam-policy.json</code>.
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
      default:
        return (
          <>
            <p className="text-sm font-semibold text-red-300">Authentication Failed</p>
            <p className="mt-1 text-sm text-red-400/80">{identityError}</p>
            {!hasExplicitCreds && (
              <p className="mt-2 text-xs text-red-400/60">
                Check that your credentials are correct and not expired.
              </p>
            )}
          </>
        )
    }
  }

  return (
    <div className="space-y-3">
      {!isIdentityValid && (
        <button
          onClick={handleVerify}
          disabled={isBusy || (!hasExplicitCreds)}
          className="btn-secondary"
          aria-label="Verify AWS identity"
          title={!hasExplicitCreds ? 'Enter Access Key ID and Secret Access Key first' : undefined}
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
              Verify Identity
            </>
          )}
        </button>
      )}

      {identityStatus === 'error' && identityError && (
        <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-4">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-red-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
            </svg>
            <div>{renderIdentityError()}</div>
          </div>
        </div>
      )}

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
    selectedMode, liveModeAvailable, identityStatus,
    triggerScan, clearError, setMode,
    clearIdentity,
  } = useScanStore()

  // Credential form state — lives here only, never in Zustand, never persisted
  const [creds, setCreds] = useState<ExplicitCreds>({
    accessKeyId: '',
    secretAccessKey: '',
    sessionToken: '',
  })

  // Track which credentials were verified — local component state only.
  // When the user changes credentials after verification, handleCredsChange
  // calls clearIdentity() which nullifies verifiedFor in the store.
  // This local state is compared in handleScan to ensure the scan uses
  // the exact same credentials that passed identity verification.
  const [verifiedCreds, setVerifiedCreds] = useState<ExplicitCreds | null>(null)

  // Clear credentials and identity state after scan completes or fails
  useEffect(() => {
    if (status === 'complete' || status === 'error') {
      setCreds({ accessKeyId: '', secretAccessKey: '', sessionToken: '' })
      setVerifiedCreds(null)
    }
  }, [status])

  // When identity verification succeeds, record the exact credentials that
  // were verified. This enables the handleScan function to verify that the
  // scan uses the same credentials that passed verification.
  useEffect(() => {
    if (identityStatus === 'verified' && hasExplicitCreds) {
      setVerifiedCreds({
        accessKeyId: creds.accessKeyId.trim(),
        secretAccessKey: creds.secretAccessKey.trim(),
        sessionToken: creds.sessionToken.trim(),
      })
    }
  }, [identityStatus]) // eslint-disable-line react-hooks/exhaustive-deps

  // Clear credentials when the Scan page unmounts.
  // Uses a ref to avoid setting state after unmount.
  const mountedRef = useRef(true)
  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      // Local state (creds, verifiedCreds) is garbage-collected with the
      // component — no explicit reset is needed or safe here, since calling
      // React state setters during unmount triggers "Can't perform a React
      // state update on an unmounted component" warnings.
    }
  }, [])

  // When credentials change, invalidate any existing identity verification
  // so the user must re-verify before scanning with the new credentials.
  // If verification is in progress, prevent credential changes to avoid
  // a race condition where stale credentials get verified.
  function handleCredsChange(newCreds: ExplicitCreds) {
    // Don't allow credential changes while identity verification is in progress
    if (identityStatus === 'checking') return
    setCreds(newCreds)
    clearIdentity()
  }

  const isIdentityValid = selectIsIdentityCurrentlyValid(useScanStore.getState())
  const totalFindings = scanResult?.findings.length ?? 0
  const isLiveResult = scanResult !== null && !scanResult.simulated
  const hasExplicitCreds = creds.accessKeyId.trim() !== '' && creds.secretAccessKey.trim() !== ''
  const canScanLive = selectedMode === 'live' && isIdentityValid && hasExplicitCreds
  const isBusy = status === 'scanning'

  function handleScan() {
    if (selectedMode === 'live' && hasExplicitCreds) {
      // Defense-in-depth: the scan must only proceed if we have a local record
      // of verified credentials that exactly match the current form values.
      // Two cases that MUST block the scan:
      //   1. verifiedCreds is null  — credentials were never verified (or were
      //      cleared by handleCredsChange), so we have no proof of identity.
      //   2. Any field differs      — user edited credentials since verification;
      //      the store's verifiedFor may already be null due to clearIdentity(),
      //      but we enforce here as an additional safety layer.
      if (
        verifiedCreds === null ||
        verifiedCreds.accessKeyId !== creds.accessKeyId.trim() ||
        verifiedCreds.secretAccessKey !== creds.secretAccessKey.trim() ||
        verifiedCreds.sessionToken !== (creds.sessionToken.trim() || '')
      ) {
        // No verified credentials or mismatch — do not scan
        return
      }
      triggerScan(undefined, {
        accessKeyId: creds.accessKeyId.trim(),
        secretAccessKey: creds.secretAccessKey.trim(),
        sessionToken: creds.sessionToken.trim() || undefined,
      })
    } else {
      triggerScan()
    }
  }

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
            liveModeAvailable={liveModeAvailable}
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
          /* Live mode: credential form + identity panel */
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
                    No resources will be created or modified.
                  </p>
                </div>
              </div>
            </div>

            {/* Region selection */}
            <RegionModeSelector />

            {/* Credential entry */}
            <CredentialForm creds={creds} onChange={handleCredsChange} disabled={isBusy} />

            {/* Identity verification */}
            <IdentityVerificationPanel creds={creds} />
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
            {hasExplicitCreds
              ? 'Verify your AWS identity above before running a live scan.'
              : 'Enter your AWS credentials above, then verify identity before scanning.'}
          </p>
        )}

        <button
          onClick={handleScan}
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
          {/* Coverage summary for live scans */}
          {isLiveResult && scanResult.coverage && (
            <CoveragePanel coverage={scanResult.coverage} />
          )}
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
