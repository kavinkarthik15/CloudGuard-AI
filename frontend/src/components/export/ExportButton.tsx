import { useRef, useState } from 'react'
import { useExport } from '../../hooks/useExport'
import { ErrorBanner } from '../shared/ErrorBanner'
import { LoadingSpinner } from '../shared/LoadingSpinner'

export function ExportButton() {
  const { canExport, exportJson, exportCsv, exportError, clearExportError, exporting } = useExport()
  const [open, setOpen] = useState(false)
  const buttonRef = useRef<HTMLButtonElement>(null)

  const handleExport = async (type: 'json' | 'csv') => {
    setOpen(false)
    if (type === 'json') await exportJson()
    else await exportCsv()
  }

  return (
    <div className="relative">
      <button
        ref={buttonRef}
        onClick={() => canExport && setOpen((v) => !v)}
        disabled={!canExport || exporting}
        aria-disabled={!canExport || exporting}
        aria-haspopup="menu"
        aria-expanded={open}
        title={!canExport ? 'Run a scan first to enable export' : 'Export findings report'}
        className="btn-secondary"
      >
        {exporting ? (
          <LoadingSpinner size="sm" label="Exporting…" />
        ) : (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
        )}
        Export Report
      </button>

      {/* Dropdown menu */}
      {open && (
        <>
          {/* Backdrop */}
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} aria-hidden="true" />
          <div
            role="menu"
            aria-label="Export format options"
            className="absolute right-0 mt-2 w-44 bg-navy-800 border border-navy-600 rounded-xl shadow-xl z-20 overflow-hidden animate-slide-down"
          >
            <button
              role="menuitem"
              onClick={() => handleExport('json')}
              className="w-full flex items-center gap-2.5 px-4 py-3 text-sm text-slate-300 hover:bg-navy-700 hover:text-slate-100 transition-colors"
            >
              <svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
              </svg>
              Download JSON
            </button>
            <button
              role="menuitem"
              onClick={() => handleExport('csv')}
              className="w-full flex items-center gap-2.5 px-4 py-3 text-sm text-slate-300 hover:bg-navy-700 hover:text-slate-100 transition-colors border-t border-navy-700"
            >
              <svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
              </svg>
              Download CSV
            </button>
          </div>
        </>
      )}

      {exportError && (
        <div className="absolute top-full mt-2 right-0 w-72 z-30">
          <ErrorBanner message={exportError} onDismiss={clearExportError} />
        </div>
      )}
    </div>
  )
}
