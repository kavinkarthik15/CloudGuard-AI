import { useEffect, useState } from 'react'
import { ExportButton } from '../components/export/ExportButton'
import { RecentFindings } from '../components/dashboard/RecentFindings'
import { SeverityChart } from '../components/dashboard/SeverityChart'
import { StatsPanel } from '../components/dashboard/StatsPanel'
import { ErrorBanner } from '../components/shared/ErrorBanner'
import { LoadingSpinner } from '../components/shared/LoadingSpinner'
import { useScanStore } from '../store/scanStore'
import type { ScanCoverage } from '../types/findings'

// ---------------------------------------------------------------------------
// CoveragePanel — displays what was actually discovered and evaluated
// ---------------------------------------------------------------------------

function CoveragePanel({ coverage }: { coverage: ScanCoverage }) {
  const s3Label = (() => {
    if (coverage.s3_buckets_requested === 0) return 'No S3 buckets found in account'
    if (coverage.s3_buckets_failed > 0) {
      return `${coverage.s3_buckets_scanned}/${coverage.s3_buckets_requested} S3 buckets evaluated (${coverage.s3_buckets_failed} failed)`
    }
    return `${coverage.s3_buckets_scanned}/${coverage.s3_buckets_requested} S3 buckets evaluated`
  })()

  const ec2Label = (() => {
    if (coverage.ec2_sgs_discovered === 0) {
      const region = coverage.scanned_regions[0] ?? 'selected region'
      return `No EC2 security groups found in ${region}`
    }
    if (coverage.ec2_sgs_failed > 0) {
      return `${coverage.ec2_sgs_evaluated}/${coverage.ec2_sgs_discovered} security groups evaluated (${coverage.ec2_sgs_failed} failed)`
    }
    return `${coverage.ec2_sgs_evaluated}/${coverage.ec2_sgs_discovered} security groups evaluated`
  })()

  const regionLabel = coverage.scanned_regions.length > 0
    ? coverage.scanned_regions.join(', ')
    : '—'

  const hasFailures = coverage.failed_regions.length > 0 ||
    coverage.s3_buckets_failed > 0 || coverage.ec2_sgs_failed > 0

  return (
    <div className={`rounded-lg border px-4 py-3 text-xs space-y-1.5 ${
      hasFailures
        ? 'border-yellow-500/20 bg-yellow-950/10'
        : 'border-navy-600 bg-navy-900/30'
    }`} aria-label="Scan coverage summary">
      <p className="text-slate-400 font-medium">Scan coverage</p>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-1.5 text-slate-300">
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500">Region:</span>
          <span className="font-mono">{regionLabel}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500">S3:</span>
          <span className={coverage.s3_buckets_requested === 0 ? 'text-slate-500 italic' : ''}>
            {s3Label}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500">EC2:</span>
          <span className={coverage.ec2_sgs_discovered === 0 ? 'text-slate-500 italic' : ''}>
            {ec2Label}
          </span>
        </div>
      </div>
      {coverage.failed_regions.length > 0 && (
        <p className="text-yellow-400">
          ⚠ Regions with errors: {coverage.failed_regions.join(', ')}
        </p>
      )}
    </div>
  )
}

// Export so ScanPage can use the same component
export { CoveragePanel }

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

export function DashboardPage() {
  const { status, scanResult, error, lastScanAt, triggerScan, clearError } = useScanStore()
  const [warningsOpen, setWarningsOpen] = useState(false)

  // Auto-trigger demo scan on first load if no result yet.
  // Only fires for demo mode — live scans are triggered explicitly by the user
  // on the Scan page. A live result must never be overwritten by an auto-demo-scan.
  useEffect(() => {
    if (scanResult === null && status === 'idle' && selectedMode === 'demo') {
      triggerScan()
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const totalFindings = scanResult?.findings.length ?? 0
  const isLiveResult = scanResult !== null && !scanResult.simulated

  // Derive subtitle from the actual scan result, not the selected mode
  const subtitle = isLiveResult
    ? `Live AWS account ${scanResult.aws_account_id ?? ''} · ${scanResult.region}`
    : 'Simulated AWS misconfiguration analysis — not real infrastructure'

  // Derive loading label from selected mode
  const { selectedMode } = useScanStore()
  const scanningLabel = selectedMode === 'live'
    ? 'Scanning real AWS configurations…'
    : 'Running security analysis on simulated configurations…'

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Page header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Security Dashboard</h1>
          <p className="mt-1 text-slate-500 text-sm">{subtitle}</p>
        </div>
        <div className="flex items-center gap-3">
          {status === 'complete' && lastScanAt && (
            <span className="text-xs text-slate-500">
              Last scan: {formatTimestamp(lastScanAt)}
            </span>
          )}
          <button
            onClick={() => triggerScan()}
            disabled={status === 'scanning'}
            className="btn-primary"
          >
            {status === 'scanning' ? (
              <>
                <LoadingSpinner size="sm" label="" />
                Scanning…
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Rescan
              </>
            )}
          </button>
          <ExportButton />
        </div>
      </div>

      {/* Error state */}
      {status === 'error' && error && (
        <ErrorBanner message={error} onDismiss={clearError} />
      )}

      {/* Loading state */}
      {status === 'scanning' && (
        <div className="card flex items-center justify-center py-16">
          <LoadingSpinner size="lg" label={scanningLabel} />
        </div>
      )}

      {/* Results */}
      {(status === 'complete' || (status === 'idle' && scanResult)) && scanResult && (
        <>
          {/* Summary stats */}
          <section aria-labelledby="stats-heading">
            <h2 id="stats-heading" className="sr-only">Finding counts by severity</h2>
            <StatsPanel summary={scanResult.summary} totalFindings={totalFindings} />
          </section>

          {/* Scan completion notice */}
          <div className={`flex items-center gap-2 text-sm text-slate-400 rounded-lg px-4 py-3 border ${
            isLiveResult
              ? 'bg-green-950/10 border-green-500/20'
              : 'bg-navy-800/50 border-navy-700'
          }`}>
            <svg className={`w-4 h-4 shrink-0 ${isLiveResult ? 'text-green-500' : 'text-green-500'}`} fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span>
              Scan complete —{' '}
              <strong className="text-slate-200">{totalFindings} findings</strong>{' '}
              identified
              {lastScanAt && <> at {formatTimestamp(lastScanAt)}</>}
              {isLiveResult && scanResult.aws_account_id && (
                <> · Account <span className="font-mono text-slate-300">{scanResult.aws_account_id}</span></>
              )}
            </span>
            {isLiveResult && (
              <span className="ml-auto text-xs text-green-400/80 font-medium">Live AWS</span>
            )}
          </div>

          {/* Zero findings note for live scans */}
          {totalFindings === 0 && isLiveResult && (
            <div className="card border-slate-600/30 bg-slate-800/20 space-y-3">
              <p className="text-sm text-slate-400">
                <strong className="text-slate-300">No findings detected</strong> in this live scan.
                This means no misconfigurations matching the current rules were found in the scanned
                resources — it does not guarantee a fully secure configuration.
              </p>
              {scanResult.coverage && (
                <CoveragePanel coverage={scanResult.coverage} />
              )}
            </div>
          )}

          {/* Coverage detail for live scans with findings */}
          {totalFindings > 0 && isLiveResult && scanResult.coverage && (
            <CoveragePanel coverage={scanResult.coverage} />
          )}

          {/* Chart + Recent findings */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <section className="card lg:col-span-2" aria-labelledby="chart-heading">
              <h2 id="chart-heading" className="text-sm font-semibold text-slate-300 mb-4">
                Severity Distribution
              </h2>
              <SeverityChart summary={scanResult.summary} />
            </section>

            <section className="card" aria-labelledby="recent-heading">
              <h2 id="recent-heading" className="text-sm font-semibold text-slate-300 mb-4">
                Recent Findings
              </h2>
              <RecentFindings findings={scanResult.findings} />
            </section>
          </div>

          {/* Warnings panel */}
          {scanResult.warnings.length > 0 && (
            <div className="card border-yellow-500/20 bg-yellow-950/10">
              <button
                onClick={() => setWarningsOpen((v) => !v)}
                className="w-full flex items-center justify-between text-left"
                aria-expanded={warningsOpen}
              >
                <span className="text-sm font-semibold text-yellow-400 flex items-center gap-2">
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  {scanResult.warnings.length} scan warning{scanResult.warnings.length !== 1 ? 's' : ''}
                </span>
                <svg className={`w-4 h-4 text-yellow-500 transition-transform ${warningsOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              {warningsOpen && (
                <ul className="mt-3 space-y-2">
                  {scanResult.warnings.map((w, i) => (
                    <li key={i} className="text-xs text-yellow-300/80 bg-yellow-950/20 rounded px-3 py-2">
                      <span className="font-mono text-yellow-400">{w.resource_id}</span>: {w.reason}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </>
      )}

      {/* Empty state for demo scan with zero findings */}
      {status === 'complete' && scanResult && totalFindings === 0 && !isLiveResult && (
        <div className="card">
          <div className="flex flex-col items-center py-12 text-center">
            <div className="w-12 h-12 rounded-full bg-green-900/30 flex items-center justify-center mb-4" aria-hidden="true">
              <svg className="w-7 h-7 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            </div>
            <p className="text-slate-300 font-semibold">No findings detected</p>
            <p className="text-slate-500 text-sm mt-1">The simulated environment looks clean.</p>
          </div>
        </div>
      )}
    </div>
  )
}
