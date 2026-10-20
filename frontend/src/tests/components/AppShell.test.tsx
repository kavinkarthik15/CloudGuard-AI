import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

// Mock SimulatedBanner since it depends on Zustand store
vi.mock('../../components/layout/SimulatedBanner', () => ({
  SimulatedBanner: () => <div data-testid="simulated-banner">Demo Mode Banner</div>,
}))

// Mock Outlet since we're not rendering child routes
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    Outlet: () => <div data-testid="outlet">Page content</div>,
  }
})

import { AppShell } from '../../components/layout/AppShell'

function renderShell() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <AppShell />
    </MemoryRouter>
  )
}

describe('AppShell', () => {
  it('renders the simulated banner', () => {
    renderShell()
    expect(screen.getByTestId('simulated-banner')).toBeInTheDocument()
  })

  it('renders the main navigation with all three links', () => {
    renderShell()
    // Desktop sidebar nav
    const navs = screen.getAllByRole('navigation')
    const mainNav = navs.find(n => n.getAttribute('aria-label') === 'Main navigation')
    expect(mainNav).toBeDefined()
    expect(mainNav).toHaveTextContent('Dashboard')
    expect(mainNav).toHaveTextContent('Findings')
    expect(mainNav).toHaveTextContent('Scan')
  })

  it('renders the mobile bottom navigation', () => {
    renderShell()
    const mobileNav = screen.getByRole('navigation', { name: 'Mobile navigation' })
    expect(mobileNav).toBeInTheDocument()
    expect(mobileNav).toHaveTextContent('Dashboard')
    expect(mobileNav).toHaveTextContent('Findings')
    expect(mobileNav).toHaveTextContent('Scan')
  })

  it('renders nav links with correct hrefs', () => {
    renderShell()
    const dashboardLinks = screen.getAllByRole('link', { name: 'Dashboard' })
    expect(dashboardLinks.length).toBeGreaterThanOrEqual(1)
    dashboardLinks.forEach(link => {
      expect(link).toHaveAttribute('href', '/dashboard')
    })
  })

  it('renders the page outlet', () => {
    renderShell()
    expect(screen.getByTestId('outlet')).toBeInTheDocument()
  })

  it('sidebar has hidden class for mobile, visible from md up', () => {
    renderShell()
    // The sidebar aside should contain hidden and md:flex classes
    const sidebar = document.querySelector('aside')
    expect(sidebar).not.toBeNull()
    expect(sidebar?.className).toContain('hidden')
    expect(sidebar?.className).toContain('md:flex')
  })

  it('mobile nav has md:hidden class', () => {
    renderShell()
    const mobileNav = screen.getByRole('navigation', { name: 'Mobile navigation' })
    expect(mobileNav.className).toContain('md:hidden')
  })
})
