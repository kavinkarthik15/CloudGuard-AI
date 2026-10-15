import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { SearchInput } from '../../components/findings/SearchInput'

describe('SearchInput', () => {
  it('renders with placeholder text', () => {
    render(<SearchInput value="" onChange={vi.fn()} />)
    expect(screen.getByPlaceholderText(/search by resource/i)).toBeInTheDocument()
  })

  it('calls onChange with typed value', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<SearchInput value="" onChange={onChange} />)

    const input = screen.getByRole('searchbox')
    await user.type(input, 's')

    expect(onChange).toHaveBeenCalledWith('s')
  })

  it('does not show clear button when value is empty', () => {
    render(<SearchInput value="" onChange={vi.fn()} />)
    expect(screen.queryByRole('button', { name: /clear search/i })).not.toBeInTheDocument()
  })

  it('shows clear button when value is non-empty', () => {
    render(<SearchInput value="ssh" onChange={vi.fn()} />)
    expect(screen.getByRole('button', { name: /clear search/i })).toBeInTheDocument()
  })

  it('calls onChange with empty string when clear button is clicked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<SearchInput value="ssh" onChange={onChange} />)

    await user.click(screen.getByRole('button', { name: /clear search/i }))
    expect(onChange).toHaveBeenCalledWith('')
  })
})
