import { SEVERITY_COLORS, type Severity } from '../../types/findings'

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const colors = SEVERITY_COLORS[severity]
  const sizeClasses = size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-xs px-2.5 py-1'

  return (
    <span
      className={`badge ${sizeClasses} ${colors.bg} ${colors.text} ${colors.border}`}
      aria-label={severity}
    >
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${colors.dot}`} aria-hidden="true" />
      {severity}
    </span>
  )
}
