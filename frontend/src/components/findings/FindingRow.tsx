import { useState } from 'react'
import type { Finding } from '../../types/findings'
import { SeverityBadge } from '../shared/SeverityBadge'

interface Props {
  finding: Finding
  isExpanded: boolean
  onToggle: () => void
}

function EvidenceBlock({ evidence }: { evidence: Record<string, unknown> }) {
  return (
    <div className="space-y-1">
      {Object.entries(evidence).map(([key, value]) => (
        <div key={key} className="flex gap-2 text-xs font-mono">
          <span className="text-slate-500 shrink-0">{key}:</span>
          <span className="text-slate-300 break-all">
            {typeof value === 'object' ? JSON.stringify(value, null, 0) : String(value)}
          </span>
        </div>
      ))}
    </div>
  )
}

export function FindingRow({ finding, isExpanded, onToggle }: Props) {
  return (
    <>
      {/* Main row */}
      <tr
        className={`border-b border-navy-700 transition-colors hover:bg-navy-800/40 ${isExpanded ? 'bg-navy-800/30' : ''}`}
      >
        <td className="px-4 py-3 text-sm text-slate-400 whitespace-nowrap">
          <span className="inline-flex items-center gap-1.5">
            {finding.resource_type === 'S3Bucket' ? (
              <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                <path d="M2 6a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                <path d="M2 12a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2v-2z" />
              </svg>
            ) : (
              <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            )}
            {finding.resource_type}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-slate-200 font-mono max-w-[200px]">
          <span className="truncate block" title={finding.resource_name}>{finding.resource_name}</span>
        </td>
        <td className="px-4 py-3">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="px-4 py-3 text-sm text-slate-300 max-w-xs">
          <span className="line-clamp-2">{finding.title}</span>
        </td>
        <td className="px-4 py-3 text-right">
          <button
            onClick={onToggle}
            aria-expanded={isExpanded}
            aria-label="Toggle finding details"
            className="p-1.5 rounded text-slate-500 hover:text-slate-300 hover:bg-navy-700 transition-colors focus-visible:ring-2 focus-visible:ring-aws-500"
          >
            <svg
              className={`w-4 h-4 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </td>
      </tr>

      {/* Expanded detail row */}
      {isExpanded && (
        <tr className="border-b border-navy-700 bg-navy-900/80 animate-slide-down">
          <td colSpan={5} className="px-6 py-5">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              {/* Evidence */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2 flex items-center gap-1.5">
                  <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                    <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
                    <path fillRule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
                  </svg>
                  Evidence
                </h4>
                <div className="bg-navy-950/80 rounded-lg p-3 border border-navy-700">
                  <EvidenceBlock evidence={finding.evidence} />
                </div>
              </div>

              {/* Risk explanation */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2 flex items-center gap-1.5">
                  <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  Risk Explanation
                </h4>
                <p className="text-sm text-slate-400 leading-relaxed">{finding.risk_explanation}</p>
              </div>

              {/* Remediation */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2 flex items-center gap-1.5">
                  <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                  Remediation
                </h4>
                <p className="text-sm text-slate-400 leading-relaxed whitespace-pre-line">{finding.remediation}</p>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
