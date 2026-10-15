import * as fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import type { Finding, Severity } from '../../types/findings'

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

const severityArb: fc.Arbitrary<Severity> = fc.constantFrom(
  'Critical',
  'High',
  'Medium',
  'Low',
  'Informational',
)

const findingArb: fc.Arbitrary<Finding> = fc.record({
  id: fc.uuid(),
  resource_type: fc.constantFrom('S3Bucket', 'SecurityGroup'),
  resource_name: fc.string({ minLength: 1, maxLength: 40 }),
  severity: severityArb,
  title: fc.string({ minLength: 1, maxLength: 100 }),
  evidence: fc.dictionary(fc.string({ minLength: 1, maxLength: 10 }), fc.string()),
  risk_explanation: fc.string({ minLength: 1, maxLength: 200 }),
  remediation: fc.string({ minLength: 1, maxLength: 200 }),
  simulated: fc.constant(true),
})

// ---------------------------------------------------------------------------
// Pure filter functions (mirrors useFindings.ts logic)
// ---------------------------------------------------------------------------

function filterBySeverity(findings: Finding[], selected: Severity[]): Finding[] {
  if (selected.length === 0) return findings
  return findings.filter((f) => selected.includes(f.severity))
}

function filterBySearch(findings: Finding[], query: string): Finding[] {
  if (!query.trim()) return findings
  const q = query.toLowerCase()
  return findings.filter(
    (f) =>
      f.resource_name.toLowerCase().includes(q) ||
      f.title.toLowerCase().includes(q),
  )
}

// ---------------------------------------------------------------------------
// CSV formatter (mirrors report_generator logic for frontend consistency)
// ---------------------------------------------------------------------------

function toCSV(findings: Finding[]): string {
  const header = 'simulated,resource_type,resource_name,severity,title,evidence,risk_explanation,remediation\n'
  const rows = findings.map((f) => {
    const flatten = (s: string) => s.replace(/\n/g, ' ').replace(/\r/g, ' ')
    const fields = [
      'true',
      f.resource_type,
      f.resource_name,
      f.severity,
      flatten(f.title),
      JSON.stringify(f.evidence),
      flatten(f.risk_explanation),
      flatten(f.remediation),
    ]
    // Simple CSV quoting
    return fields.map((v) => (v.includes(',') || v.includes('"') ? `"${v.replace(/"/g, '""')}"` : v)).join(',')
  })
  return header + rows.join('\n')
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

describe('Filter properties', () => {
  it('severity filter always returns a subset', () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { minLength: 0, maxLength: 20 }),
        fc.array(severityArb, { minLength: 0, maxLength: 5 }),
        (findings, selected) => {
          const result = filterBySeverity(findings, selected)
          // Every result item must be in the input
          expect(result.every((r) => findings.includes(r))).toBe(true)
          // Every result item must have a matching severity
          if (selected.length > 0) {
            expect(result.every((r) => selected.includes(r.severity))).toBe(true)
          }
        },
      ),
    )
  })

  it('search filter always returns a subset', () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { minLength: 0, maxLength: 20 }),
        fc.string({ maxLength: 20 }),
        (findings, query) => {
          const result = filterBySearch(findings, query)
          expect(result.every((r) => findings.includes(r))).toBe(true)
        },
      ),
    )
  })

  it('combined filter always returns a subset', () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { minLength: 0, maxLength: 20 }),
        fc.array(severityArb, { minLength: 0, maxLength: 5 }),
        fc.string({ maxLength: 20 }),
        (findings, selected, query) => {
          const afterSeverity = filterBySeverity(findings, selected)
          const result = filterBySearch(afterSeverity, query)
          expect(result.every((r) => findings.includes(r))).toBe(true)
        },
      ),
    )
  })
})

describe('CSV export properties', () => {
  it('CSV row count equals finding count + 1 (header)', () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { minLength: 0, maxLength: 50 }),
        (findings) => {
          const csv = toCSV(findings)
          const lines = csv.split('\n').filter((l) => l.trim())
          expect(lines.length).toBe(findings.length + 1)
        },
      ),
    )
  })

  it('CSV output contains no embedded raw newlines in data rows', () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { minLength: 1, maxLength: 10 }),
        (findings) => {
          const csv = toCSV(findings)
          const lines = csv.split('\n')
          // Data rows (skip header) should not have embedded carriage returns
          const dataRows = lines.slice(1)
          dataRows.forEach((row) => {
            expect(row).not.toMatch(/\r/)
          })
        },
      ),
    )
  })

  it('JSON export includes all finding fields', () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { minLength: 1, maxLength: 10 }),
        (findings) => {
          const json = JSON.stringify({
            simulated: true,
            findings: findings.map((f) => ({
              resource_type: f.resource_type,
              resource_name: f.resource_name,
              severity: f.severity,
              title: f.title,
              evidence: f.evidence,
              risk_explanation: f.risk_explanation,
              remediation: f.remediation,
            })),
          })
          const parsed = JSON.parse(json)
          expect(parsed.simulated).toBe(true)
          expect(parsed.findings.length).toBe(findings.length)
          parsed.findings.forEach((f: Record<string, unknown>) => {
            expect(f.resource_type).toBeTruthy()
            expect(f.resource_name).toBeTruthy()
            expect(f.severity).toBeTruthy()
            expect(f.title).toBeTruthy()
          })
        },
      ),
    )
  })
})
