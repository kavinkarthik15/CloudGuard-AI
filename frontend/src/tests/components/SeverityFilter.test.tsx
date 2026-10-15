import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { SeverityFilter } from '../../components/findings/SeverityFilter'
import type { Severity } from '../../types/findings'

describe('SeverityFilter', () => {
  it('renders all five severity options', () => {
    render(<SeverityFilter selected={[]} onChange={vi.fn()} />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(screen.getByText('Medium')).toBeInTheDocument()
    expect(screen.getByText('Low')).toBeInTheDocument()
    expect(screen.getByText('Informational')).toBeInTheDocument()
  })

  it('calls onChange with added severity when checkbox is clicked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<SeverityFilter selected={[]} onChange={onChange} />)

    const criticalLabel = screen.getByRole('checkbox', { name: /filter by critical/i })
    await user.click(criticalLabel)

    expect(onChange).toHaveBeenCalledWith(['Critical'])
  })

  it('calls onChange with removed severity when already-selected checkbox is clicked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const selected: Severity[] = ['Critical', 'High']
    render(<SeverityFilter selected={selected} onChange={onChange} />)

    const criticalLabel = screen.getByRole('checkbox', { name: /filter by critical/i })
    await user.click(criticalLabel)

    expect(onChange).toHaveBeenCalledWith(['High'])
  })

  it('checkboxes are checked according to selected prop', () => {
    render(<SeverityFilter selected={['Critical', 'High']} onChange={vi.fn()} />)
    const criticalCb = screen.getByRole('checkbox', { name: /filter by critical/i }) as HTMLInputElement
    const highCb = screen.getByRole('checkbox', { name: /filter by high/i }) as HTMLInputElement
    const mediumCb = screen.getByRole('checkbox', { name: /filter by medium/i }) as HTMLInputElement

    expect(criticalCb.checked).toBe(true)
    expect(highCb.checked).toBe(true)
    expect(mediumCb.checked).toBe(false)
  })
})
