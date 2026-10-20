/**
 * Export hook — downloads findings for the exact scan currently in the store.
 *
 * Correctness guarantee:
 *   The scan_id from the store's ScanResult is passed to the backend's
 *   scan-id-specific export endpoints (/api/export/{scan_id}/json|csv).
 *   If the scan has expired (server restart, eviction) the backend returns
 *   SCAN_NOT_FOUND and the user sees a clear, actionable error message.
 *   No stale or cross-mode export is possible.
 */
import { useState } from 'react'
import { ApiError, scanApi } from '../api/client'
import { useScanStore } from '../store/scanStore'

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function todayDateString(): string {
  return new Date().toISOString().slice(0, 10)
}

export function useExport() {
  const { status, scanResult } = useScanStore()
  const [exportError, setExportError] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)

  // Export is only available when a completed scan with findings exists.
  const canExport =
    status === 'complete' && scanResult !== null && scanResult.findings.length > 0

  const clearExportError = () => setExportError(null)

  const exportJson = async () => {
    if (!scanResult) return
    setExportError(null)
    setExporting(true)
    try {
      const blob = await scanApi.exportJson(scanResult.scan_id)
      const suffix = scanResult.simulated ? 'demo' : 'live'
      downloadBlob(blob, `cloudguard-findings-${todayDateString()}-${suffix}.json`)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'SCAN_NOT_FOUND') {
        setExportError(
          'This scan is no longer available on the server (it may have expired or the ' +
          'server restarted). Re-run the scan and export immediately after it completes.'
        )
      } else {
        setExportError(
          err instanceof ApiError ? err.message : 'Failed to export JSON report.',
        )
      }
    } finally {
      setExporting(false)
    }
  }

  const exportCsv = async () => {
    if (!scanResult) return
    setExportError(null)
    setExporting(true)
    try {
      const blob = await scanApi.exportCsv(scanResult.scan_id)
      const suffix = scanResult.simulated ? 'demo' : 'live'
      downloadBlob(blob, `cloudguard-findings-${todayDateString()}-${suffix}.csv`)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'SCAN_NOT_FOUND') {
        setExportError(
          'This scan is no longer available on the server (it may have expired or the ' +
          'server restarted). Re-run the scan and export immediately after it completes.'
        )
      } else {
        setExportError(
          err instanceof ApiError ? err.message : 'Failed to export CSV report.',
        )
      }
    } finally {
      setExporting(false)
    }
  }

  return { canExport, exportJson, exportCsv, exportError, clearExportError, exporting }
}
