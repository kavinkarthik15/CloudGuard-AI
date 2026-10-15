import { SEVERITY_COLORS, SEVERITY_ORDER, type Severity } from '../../types/findings'

interface Props {
  summary: Record<string, number> | null
  totalFindings: number
}

export function StatsPanel({ summary, totalFindings }: Props) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
      {SEVERITY_ORDER.map((severity: Severity) => {
        const count = summary?.[severity] ?? 0
        const colors = SEVERITY_COLORS[severity]
        return (
          <div
            key={severity}
            className={`card border ${colors.card} flex flex-col gap-1 transition-all duration-200`}
            aria-label={`${severity}: ${count} findings`}
          >
            <div className="flex items-center justify-between">
              <span className={`text-xs font-semibold ${colors.text} uppercase tracking-wide`}>
                {severity}
              </span>
              <span className={`w-2 h-2 rounded-full ${colors.dot}`} aria-hidden="true" />
            </div>
            <div className={`text-2xl font-bold ${colors.text} tabular-nums`}>
              {count}
            </div>
            <div className="text-xs text-slate-500">
              {count === 1 ? 'finding' : 'findings'}
            </div>
          </div>
        )
      })}
    </div>
  )
}
