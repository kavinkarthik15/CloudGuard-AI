/**
 * Global scan state store using Zustand.
 * Holds the current scan status, result, and error.
 */
import { create } from 'zustand'
import { ApiError, scanApi } from '../api/client'
import type { ScanResult } from '../types/findings'

export type ScanStatus = 'idle' | 'scanning' | 'complete' | 'error'

interface ScanState {
  status: ScanStatus
  scanResult: ScanResult | null
  error: string | null
  lastScanAt: string | null
}

interface ScanActions {
  triggerScan: (region?: string) => Promise<void>
  clearError: () => void
}

export const useScanStore = create<ScanState & ScanActions>((set) => ({
  status: 'idle',
  scanResult: null,
  error: null,
  lastScanAt: null,

  triggerScan: async (region?: string) => {
    set({ status: 'scanning', error: null })
    try {
      const result = await scanApi.triggerScan({ region })
      set({
        status: 'complete',
        scanResult: result,
        lastScanAt: new Date().toISOString(),
        error: null,
      })
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : 'An unexpected error occurred. Please try again.'
      set({ status: 'error', error: message })
    }
  },

  clearError: () => {
    set((state) => ({
      error: null,
      status: state.status === 'error' ? 'idle' : state.status,
    }))
  },
}))
