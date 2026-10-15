import { useEffect, useMemo, useRef, useState } from 'react'
import { useScanStore } from '../store/scanStore'
import type { Finding, Severity } from '../types/findings'

export function useFindings() {
  const { scanResult } = useScanStore()
  const [searchQuery, setSearchQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>([])
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Debounce search query (≤200ms)
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      setDebouncedQuery(searchQuery)
    }, 150)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [searchQuery])

  const allFindings: Finding[] = scanResult?.findings ?? []

  const filteredFindings = useMemo(() => {
    let result = allFindings

    // Severity filter
    if (selectedSeverities.length > 0) {
      result = result.filter((f) => selectedSeverities.includes(f.severity))
    }

    // Search filter (case-insensitive partial match)
    if (debouncedQuery.trim()) {
      const q = debouncedQuery.toLowerCase()
      result = result.filter(
        (f) =>
          f.resource_name.toLowerCase().includes(q) ||
          f.title.toLowerCase().includes(q),
      )
    }

    return result
  }, [allFindings, selectedSeverities, debouncedQuery])

  return {
    filteredFindings,
    allFindings,
    searchQuery,
    setSearchQuery,
    selectedSeverities,
    setSelectedSeverities,
  }
}
