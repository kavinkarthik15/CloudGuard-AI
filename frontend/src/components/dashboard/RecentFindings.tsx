import type { Finding } from '../../types/findings'
import { EmptyState } from '../shared/EmptyState'
import { SeverityBadge } from '../shared/SeverityBadge'

interface Props {
  findings: Finding[]
}

function truncate(text: string, maxLen = 80): string {
  return text.length > maxLen ? text.slice(0, maxLen - 1) + '…' : text
}

export function RecentFindings({ findings }: Props) {
  const recent = findings.slice(0, 5)

  if (recent.length === 0) {
    return <EmptyState title="No recent findings" description="Run a scan to see results." />
  }

  return (
    <ul className="space-y-2" aria-label="Recent findings">
      {recent.map((finding) => (
        <li
          key={finding.id}
          className="flex items-start gap-3 p-3 rounded-lg bg-navy-900/50 border border-navy-700 hover:border-navy-600 transition-colors"
        >
          <div className="shrink-0 mt-0.5">
            <SeverityBadge severity={finding.severity} size="sm" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm text-slate-200 font-medium leading-snug truncate" title={finding.title}>
              {truncate(finding.title)}
            </p>
            <p className="text-xs text-slate-500 mt-0.5 truncate">{finding.resource_name}</p>
          </div>
        </li>
      ))}
    </ul>
  )
}
