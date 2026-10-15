import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { SEVERITY_ORDER, type Severity } from '../../types/findings'
import { EmptyState } from '../shared/EmptyState'

// Raw hex colors for Recharts (which doesn't use Tailwind classes)
const CHART_COLORS: Record<Severity, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6',
  Informational: '#64748b',
}

interface Props {
  summary: Record<string, number> | null
}

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ value: number; payload: { severity: string } }>
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  const { value, payload: item } = payload[0]
  return (
    <div className="bg-navy-800 border border-navy-600 rounded-lg px-3 py-2 text-sm shadow-lg">
      <div className="text-slate-300 font-medium">{item.severity}</div>
      <div className="text-slate-100 font-bold">{value} {value === 1 ? 'finding' : 'findings'}</div>
    </div>
  )
}

export function SeverityChart({ summary }: Props) {
  const allZero = !summary || SEVERITY_ORDER.every(s => (summary[s] ?? 0) === 0)

  if (allZero) {
    return (
      <div role="img" aria-label="Severity distribution chart — no findings">
        <EmptyState title="No findings to chart" description="Run a scan to see severity distribution." />
      </div>
    )
  }

  const data = SEVERITY_ORDER.map(severity => ({
    severity,
    count: summary?.[severity] ?? 0,
    color: CHART_COLORS[severity],
  }))

  return (
    <div role="img" aria-label="Severity distribution chart">
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <XAxis
            dataKey="severity"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: '#64748b', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry) => (
              <Cell key={entry.severity} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
