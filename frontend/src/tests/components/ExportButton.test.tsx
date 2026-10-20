import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { ExportButton } from '../../components/export/ExportButton'
import * as exportHook from '../../hooks/useExport'

// Mock the useExport hook
vi.mock('../../hooks/useExport')

const mockUseExport = vi.mocked(exportHook.useExport)

function setupMock(overrides: Partial<ReturnType<typeof exportHook.useExport>> = {}) {
  mockUseExport.mockReturnValue({
    canExport: false,
    exportJson: vi.fn(),
    exportCsv: vi.fn(),
    exportError: null,
    clearExportError: vi.fn(),
    exporting: false,
    ...overrides,
  })
}

describe('ExportButton', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the Export Report button', () => {
    setupMock({ canExport: false })
    render(<ExportButton />)
    expect(screen.getByRole('button', { name: /export report/i })).toBeInTheDocument()
  })

  it('is disabled when canExport is false', () => {
    setupMock({ canExport: false })
    render(<ExportButton />)
    const button = screen.getByRole('button', { name: /export report/i })
    expect(button).toBeDisabled()
  })

  it('is enabled when canExport is true', () => {
    setupMock({ canExport: true })
    render(<ExportButton />)
    const button = screen.getByRole('button', { name: /export report/i })
    expect(button).not.toBeDisabled()
  })

  it('shows format picker when clicked with canExport=true', async () => {
    const user = userEvent.setup()
    setupMock({ canExport: true })
    render(<ExportButton />)

    await user.click(screen.getByRole('button', { name: /export report/i }))

    expect(screen.getByText('Download JSON')).toBeInTheDocument()
    expect(screen.getByText('Download CSV')).toBeInTheDocument()
  })

  it('calls exportJson when JSON option is clicked', async () => {
    const user = userEvent.setup()
    const exportJson = vi.fn()
    setupMock({ canExport: true, exportJson })
    render(<ExportButton />)

    await user.click(screen.getByRole('button', { name: /export report/i }))
    await user.click(screen.getByText('Download JSON'))

    expect(exportJson).toHaveBeenCalledOnce()
  })

  it('calls exportCsv when CSV option is clicked', async () => {
    const user = userEvent.setup()
    const exportCsv = vi.fn()
    setupMock({ canExport: true, exportCsv })
    render(<ExportButton />)

    await user.click(screen.getByRole('button', { name: /export report/i }))
    await user.click(screen.getByText('Download CSV'))

    expect(exportCsv).toHaveBeenCalledOnce()
  })

  it('displays error notification when exportError is set', () => {
    setupMock({ canExport: true, exportError: 'Export failed — server error.' })
    render(<ExportButton />)
    expect(screen.getByText('Export failed — server error.')).toBeInTheDocument()
  })

  it('keeps Export Report button enabled when an error occurs', () => {
    setupMock({ canExport: true, exportError: 'Some error' })
    render(<ExportButton />)
    const button = screen.getByRole('button', { name: /export report/i })
    expect(button).not.toBeDisabled()
  })

  it('displays SCAN_NOT_FOUND error with helpful message', () => {
    const scanNotFoundMsg =
      'This scan is no longer available on the server (it may have expired or the ' +
      'server restarted). Re-run the scan and export immediately after it completes.'
    setupMock({ canExport: true, exportError: scanNotFoundMsg })
    render(<ExportButton />)
    expect(screen.getByText(scanNotFoundMsg)).toBeInTheDocument()
    // Button must still be enabled so user can re-run
    expect(screen.getByRole('button', { name: /export report/i })).not.toBeDisabled()
  })
})
