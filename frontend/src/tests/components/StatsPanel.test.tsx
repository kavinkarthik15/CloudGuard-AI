import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { StatsPanel } from '../../components/dashboard/StatsPanel'

const mockSummary = {
  Critical: 3,
  High: 5,
  Medium: 2,
  Low: 1,
  Informational: 4,
}

describe('StatsPanel', () => {
  it('renders all five severity labels', () => {
    render(<StatsPanel summary={mockSummary} totalFindings={15} />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(screen.getByText('Medium')).toBeInTheDocument()
    expect(screen.getByText('Low')).toBeInTheDocument()
    expect(screen.getByText('Informational')).toBeInTheDocument()
  })

  it('renders correct counts for each severity', () => {
    render(<StatsPanel summary={mockSummary} totalFindings={15} />)
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
  })

  it('renders with null summary without crashing', () => {
    render(<StatsPanel summary={null} totalFindings={0} />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('shows zero counts when summary is null', () => {
    render(<StatsPanel summary={null} totalFindings={0} />)
    const zeros = screen.getAllByText('0')
    expect(zeros.length).toBe(5)
  })
})
