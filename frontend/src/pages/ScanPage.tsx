import { useState } from 'react'
import { ErrorBanner } from '../components/shared/ErrorBanner'
import { LoadingSpinner } from '../components/shared/LoadingSpinner'
import { useScanStore } from '../store/scanStore'

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

export function ScanPage() {
  const { status, scanResult, error, lastScanAt, triggerScan, clearError } = useScanStore()
  const [region, setRegion] = useState('us-east-1')

  const handleScan = () => {
    triggerScan(region || 'us-east-1')
  }

  const totalFindings = scanResult?.findings.length ?? 0

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Security Scan</h1>
        <p className="mt-1 text-slate-500 text-sm">
          Evaluate simulated AWS resource configurations for security misconfigurations.
        </p>
      </div>

      {/* Pre-scan informational notice — always visible */}
      <div className="card border-blue-500/20 bg-blue-950/10">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
          <div>
            <p className="text-sm font-semibold text-blue-300">Simulated Data — Session 1</p>
            <p className="mt-1 text-sm text-blue-400/80 leading-relaxed">
              CloudGuard AI evaluates <strong>simulated AWS resource configurations</strong> loaded
              from JSON fixtures. All findings reflect simulated data only — no real AWS API calls
              are made and no real infrastructure is scanned. A future Session 2 will integrate
              real AWS scanning via Boto3 using read-only permissions.
            </p>
          </div>
        </div>
      </div>

      {/* Scan controls */}
      <div className="card space-y-5">
        <h2 className="text-sm font-semibold text-slate-300">Scan Configuration</h2>

        <div>
          <label htmlFor="region" className="block text-sm text-slate-400 mb-1.5">
            AWS Region <span className="text-slate-600 text-xs">(stored in scan metadata)</span>
          </label>
          <input
            id="region"
            type="text"
            value={region}
            onChange={(e) => setRegion(e.target.value)}
            placeholder="us-east-1"
            className="input max-w-xs"
            disabled={status === 'scanning'}
          />
          <p className="mt-1 text-xs text-slate-600">
            In Session 1 this is stored in metadata only. Real region scans require Boto3 (Session 2).
          </p>
        </div>

        <button
          onClick={handleScan}
          disabled={status === 'scanning'}
          aria-disabled={status === 'scanning'}
          className="btn-primary"
        >
          {status === 'scanning' ? (
            <>
              <LoadingSpinner size="sm" label="" />
              Scan in progress…
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
        <div className="card border-green-500/20 bg-green-950/10">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-full bg-green-900/40 flex items-center justify-center shrink-0">
              <svg className="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-green-300">Scan completed successfully</p>
              <p className="mt-1 text-sm text-green-400/80">
                <strong className="text-green-300">{totalFindings} findings</strong> identified
                {lastScanAt && <> at {formatTimestamp(lastScanAt)}</>}.
                Region: <span className="font-mono">{scanResult.region}</span>.
              </p>
              {scanResult.warnings.length > 0 && (
                <p className="mt-1 text-xs text-yellow-400">
                  {scanResult.warnings.length} resource{scanResult.warnings.length !== 1 ? 's' : ''} could not be processed.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Severity breakdown */}
      {status === 'complete' && scanResult && totalFindings > 0 && (
        <div className="card">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Findings by Severity</h2>
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
        </div>
      )}
    </div>
  )
}
