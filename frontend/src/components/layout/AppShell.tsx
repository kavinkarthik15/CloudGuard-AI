import { NavLink, Outlet } from 'react-router-dom'
import { SimulatedBanner } from './SimulatedBanner'
import { useScanStore } from '../../store/scanStore'

interface NavItem {
  to: string
  label: string
  icon: React.ReactNode
}

const navItems: NavItem[] = [
  {
    to: '/dashboard',
    label: 'Dashboard',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
      </svg>
    ),
  },
  {
    to: '/findings',
    label: 'Findings',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    ),
  },
  {
    to: '/scan',
    label: 'Scan',
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
    ),
  },
]

export function AppShell() {
  const { scanResult } = useScanStore()
  const isLiveResult = scanResult !== null && scanResult.simulated === false
  return (
    <div className="min-h-screen flex flex-col bg-navy-950">
      {/* Persistent mode-aware banner — always visible, not dismissible */}
      <SimulatedBanner />

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar navigation — hidden on mobile, visible from md (768px) up */}
        <aside className="hidden md:flex w-60 shrink-0 bg-navy-900 border-r border-navy-700 flex-col">
          {/* Logo */}
          <div className="px-5 py-5 border-b border-navy-700">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-aws-500 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-navy-950" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M12 1.5a10.5 10.5 0 100 21 10.5 10.5 0 000-21zm0 1.5a9 9 0 110 18A9 9 0 0112 3zm-.75 4.5v5.25l4.5 2.25-.75 1.5-5.25-2.625V7.5h1.5z" />
                </svg>
              </div>
              <div>
                <div className="text-slate-100 font-semibold text-sm leading-tight">CloudGuard AI</div>
                <div className="text-slate-500 text-xs">Security Auditor</div>
              </div>
            </div>
          </div>

          {/* Nav links */}
          <nav className="flex-1 px-3 py-4 space-y-1" aria-label="Main navigation">
            {navItems.map(({ to, label, icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                aria-label={label}
              >
                {icon}
                <span>{label}</span>
              </NavLink>
            ))}
          </nav>

          {/* Footer */}
          <div className="px-4 py-4 border-t border-navy-700">
            <div className="text-xs text-slate-600 leading-relaxed">
              {isLiveResult ? (
                <>
                  <div className="font-medium text-green-500">Live AWS Mode</div>
                  <div className="mt-0.5">Real AWS API data</div>
                </>
              ) : (
                <>
                  <div className="font-medium text-amber-500">Demo Mode</div>
                  <div className="mt-0.5">Simulated data — no AWS calls</div>
                </>
              )}
            </div>
          </div>
        </aside>

        {/* Main content — takes full width on mobile */}
        <main className="flex-1 overflow-auto pb-16 md:pb-0" id="main-content">
          <Outlet />
        </main>
      </div>

      {/* Mobile bottom navigation — visible below md breakpoint only */}
      <nav
        className="md:hidden fixed bottom-0 inset-x-0 bg-navy-900 border-t border-navy-700 flex z-50"
        aria-label="Mobile navigation"
      >
        {navItems.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex flex-col items-center justify-center flex-1 py-2 text-xs gap-1 transition-colors focus-visible:ring-2 focus-visible:ring-aws-500 ${
                isActive ? 'text-aws-500' : 'text-slate-500 hover:text-slate-300'
              }`
            }
            aria-label={label}
          >
            {icon}
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
    </div>
  )
}
