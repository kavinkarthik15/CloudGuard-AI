/**
 * Mode-aware top banner.
 *
 * Displays the amber "Demo Mode — Simulated Data" banner when the current
 * scan result is simulated (ScanResult.simulated === true, or no result yet).
 *
 * Displays a green "Live AWS" indicator when a real scan result is present
 * (ScanResult.simulated === false). This is based on the RESULT, not the
 * selected mode, so a failed live scan never shows a live indicator.
 *
 * The demo banner is never dismissible. The live indicator is persistent.
 */
import { useScanStore } from '../../store/scanStore'

export function SimulatedBanner() {
  const { scanResult } = useScanStore()

  // Determine provenance from the actual scan result, not from selectedMode.
  // No result yet → show demo banner (safe default).
  const isLiveResult = scanResult !== null && scanResult.simulated === false

  if (isLiveResult) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="w-full bg-green-900/20 border-b border-green-500/30 px-4 py-2 flex items-center justify-center gap-2.5 text-green-400 text-xs font-medium"
      >
        <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" aria-hidden="true" />
        <span>
          <strong className="font-semibold">Live AWS Scan</strong>
          {scanResult.aws_account_id && (
            <> · Account <span className="font-mono">{scanResult.aws_account_id}</span></>
          )}
          {' '}· Region <span className="font-mono">{scanResult.region}</span>
          {' '}· All findings reflect real AWS configuration data.
        </span>
      </div>
    )
  }

  return (
    <div
      role="alert"
      aria-live="polite"
      className="w-full bg-amber-500/10 border-b border-amber-500/30 px-4 py-2 flex items-center justify-center gap-2.5 text-amber-400 text-xs font-medium"
    >
      <svg className="w-3.5 h-3.5 shrink-0" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
        <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
      </svg>
      <span>
        <strong className="font-semibold">Demo Mode — Simulated Data</strong>
        {' '}· All findings are generated from simulated AWS configurations, not real infrastructure.
      </span>
    </div>
  )
}
