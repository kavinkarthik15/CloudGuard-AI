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

  const canExport =
    status === 'complete' && scanResult !== null && scanResult.findings.length > 0

  const clearExportError = () => setExportError(null)

  const exportJson = async () => {
    setExportError(null)
    setExporting(true)
    try {
      const blob = await scanApi.exportJson()
      downloadBlob(blob, `cloudguard-findings-${todayDateString()}.json`)
    } catch (err) {
      setExportError(
        err instanceof ApiError ? err.message : 'Failed to export JSON report.',
      )
    } finally {
      setExporting(false)
    }
  }

  const exportCsv = async () => {
    setExportError(null)
    setExporting(true)
    try {
      const blob = await scanApi.exportCsv()
      downloadBlob(blob, `cloudguard-findings-${todayDateString()}.csv`)
    } catch (err) {
      setExportError(
        err instanceof ApiError ? err.message : 'Failed to export CSV report.',
      )
    } finally {
      setExporting(false)
    }
  }

  return { canExport, exportJson, exportCsv, exportError, clearExportError, exporting }
}
