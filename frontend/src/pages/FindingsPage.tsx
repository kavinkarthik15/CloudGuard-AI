import { useState } from 'react'
import { ExportButton } from '../components/export/ExportButton'
import { SeverityFilter } from '../components/findings/SeverityFilter'
import { SearchInput } from '../components/findings/SearchInput'
import { FindingsTable } from '../components/findings/FindingsTable'
import { ErrorBanner } from '../components/shared/ErrorBanner'
import { LoadingSpinner } from '../components/shared/LoadingSpinner'
import { EmptyState } from '../components/shared/EmptyState'
import { useFindings } from '../hooks/useFindings'
import { useScanStore } from '../store/scanStore'

export function FindingsPage() {
  const { status, scanResult, error, clearError } = useScanStore()
  const {
    filteredFindings,
    allFindings,
    searchQuery,
    setSearchQuery,
    selectedSeverities,
    setSelectedSeverities,
  } = useFindings()
  const [warningsOpen, setWarningsOpen] = useState(false)

  const isFiltered =
    selectedSeverities.length > 0 || searchQuery.trim().length > 0

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Security Findings</h1>
          <p className="mt-1 text-slate-500 text-sm">
            {status === 'complete'
              ? `${allFindings.length} total findings from simulated resource analysis`
              : 'Run a scan to see findings'}
          </p>
        </div>
        <ExportButton />
      </div>

      {/* Error */}
      {status === 'error' && error && (
        <ErrorBanner message={error} onDismiss={clearError} />
      )}

      {/* Loading */}
      {status === 'scanning' && (
        <div className="card flex items-center justify-center py-16">
          <LoadingSpinner size="lg" label="Scanning simulated configurations…" />
        </div>
      )}

      {/* No scan yet */}
      {status === 'idle' && !scanResult && (
        <EmptyState
          title="Run a scan to see findings"
          description="Navigate to Scan to trigger a simulated security analysis."
        />
      )}

      {/* Results */}
      {(status === 'complete' || (status !== 'scanning' && scanResult)) && scanResult && (
        <>
          {/* Filters */}
          <div className="card space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex-1 min-w-60">
                <SearchInput value={searchQuery} onChange={setSearchQuery} />
              </div>
              <SeverityFilter
                selected={selectedSeverities}
                onChange={setSelectedSeverities}
              />
            </div>

            {/* Result count */}
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>
                Showing{' '}
                <strong className="text-slate-300">{filteredFindings.length}</strong>
                {' '}of{' '}
                <strong className="text-slate-300">{allFindings.length}</strong>
                {' '}findings
                {isFiltered && (
                  <button
                    onClick={() => {
                      setSearchQuery('')
                      setSelectedSeverities([])
                    }}
                    className="ml-2 text-aws-500 hover:text-aws-400 underline"
                  >
                    Clear filters
                  </button>
                )}
              </span>
            </div>
          </div>

          {/* Warnings */}
          {scanResult.warnings.length > 0 && (
            <div className="card border-yellow-500/20 bg-yellow-950/10">
              <button
                onClick={() => setWarningsOpen((v) => !v)}
                className="w-full flex items-center justify-between text-left"
                aria-expanded={warningsOpen}
              >
                <span className="text-sm font-semibold text-yellow-400 flex items-center gap-2">
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

          {/* Table */}
          <FindingsTable findings={filteredFindings} />
        </>
      )}
    </div>
  )
}
