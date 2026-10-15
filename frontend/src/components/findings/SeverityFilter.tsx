import { SEVERITY_ORDER, type Severity } from '../../types/findings'
import { SeverityBadge } from '../shared/SeverityBadge'

interface Props {
  selected: Severity[]
  onChange: (selected: Severity[]) => void
}

export function SeverityFilter({ selected, onChange }: Props) {
  const toggle = (severity: Severity) => {
    if (selected.includes(severity)) {
      onChange(selected.filter((s) => s !== severity))
    } else {
      onChange([...selected, severity])
    }
  }

  return (
    <div role="group" aria-label="Filter by severity" className="flex flex-wrap gap-2">
      {SEVERITY_ORDER.map((severity) => {
        const checked = selected.includes(severity)
        return (
          <label
            key={severity}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border cursor-pointer transition-all duration-150 text-sm select-none
              ${checked
                ? 'bg-navy-700 border-navy-500 text-slate-100'
                : 'bg-navy-900 border-navy-700 text-slate-400 hover:border-navy-600 hover:text-slate-300'
              }`}
          >
            <input
              type="checkbox"
              id={`filter-${severity}`}
              name={`filter-${severity}`}
              checked={checked}
              onChange={() => toggle(severity)}
              aria-label={`Filter by ${severity}`}
              className="sr-only"
            />
            <SeverityBadge severity={severity} size="sm" />
          </label>
        )
      })}
    </div>
  )
}
