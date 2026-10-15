import { useState } from 'react'
import type { Finding } from '../../types/findings'
import { EmptyState } from '../shared/EmptyState'
import { FindingRow } from './FindingRow'

interface Props {
  findings: Finding[]
}

export function FindingsTable({ findings }: Props) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())

  const toggleRow = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  if (findings.length === 0) {
    return (
      <EmptyState
        title="No findings match the current filters"
        description="Try clearing the search or adjusting the severity filters."
      />
    )
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-navy-700">
      <table className="w-full" role="table">
        <caption className="sr-only">Security findings table</caption>
        <thead>
          <tr className="border-b border-navy-700 bg-navy-900/80">
            <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide w-32">
              Resource Type
            </th>
            <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide w-48">
              Resource Name
            </th>
            <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide w-36">
              Severity
            </th>
            <th scope="col" className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
              Finding Title
            </th>
            <th scope="col" className="px-4 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wide w-16">
              Details
            </th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              isExpanded={expandedIds.has(finding.id)}
              onToggle={() => toggleRow(finding.id)}
            />
          ))}
        </tbody>
      </table>
    </div>
  )
}
