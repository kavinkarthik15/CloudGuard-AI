import { useEffect } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
import { DashboardPage } from './pages/DashboardPage'
import { FindingsPage } from './pages/FindingsPage'
import { ScanPage } from './pages/ScanPage'
import { useScanStore } from './store/scanStore'

export default function App() {
  const { loadHealth } = useScanStore()

  // Fetch backend health on startup to populate liveModeAvailable.
  // The backend enforces LIVE_AWS_DISABLED regardless of this check.
  useEffect(() => {
    loadHealth()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Routes>
      <Route path="/" element={<AppShell />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="scan" element={<ScanPage />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  )
}
