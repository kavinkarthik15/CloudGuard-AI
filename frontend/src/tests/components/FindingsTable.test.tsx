import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { FindingsTable } from '../../components/findings/FindingsTable'
import type { Finding } from '../../types/findings'

const mockFindings: Finding[] = [
  {
    id: '1',
    resource_type: 'S3Bucket',
    resource_name: 'simulated-bucket-1',
    severity: 'Critical',
    title: 'Bucket is publicly accessible',
    evidence: { disabled: ['block_public_acls'], acl: 'AllUsers' },
    risk_explanation: 'This finding is based on simulated configuration data. Risk here.',
    remediation: 'Enable all block settings.',
    simulated: true,
  },
  {
    id: '2',
    resource_type: 'SecurityGroup',
    resource_name: 'sg-sim-0001',
    severity: 'High',
    title: 'SSH open to world',
    evidence: { port: 22, cidr: '0.0.0.0/0' },
    risk_explanation: 'This finding is based on simulated configuration data.',
    remediation: 'Restrict SSH.',
    simulated: true,
  },
  {
    id: '3',
    resource_type: 'S3Bucket',
    resource_name: 'simulated-bucket-2',
    severity: 'Informational',
    title: 'SSE-S3 only',
    evidence: { sse_algorithm: 'AES256' },
    risk_explanation: 'This finding is based on simulated configuration data.',
    remediation: 'Consider KMS.',
    simulated: true,
  },
]

describe('FindingsTable', () => {
  it('renders the correct number of rows', () => {
    render(<FindingsTable findings={mockFindings} />)
    // Each finding has a main row; check resource names are visible
    expect(screen.getByText('simulated-bucket-1')).toBeInTheDocument()
    expect(screen.getByText('sg-sim-0001')).toBeInTheDocument()
    expect(screen.getByText('simulated-bucket-2')).toBeInTheDocument()
  })

  it('shows empty state when no findings', () => {
    render(<FindingsTable findings={[]} />)
    expect(screen.getByText(/no findings match/i)).toBeInTheDocument()
  })

  it('expands a row to show evidence, risk explanation, and remediation', async () => {
    const user = userEvent.setup()
    render(<FindingsTable findings={mockFindings} />)

    // Find the first toggle button
    const toggleButtons = screen.getAllByRole('button', { name: /toggle finding details/i })
    await user.click(toggleButtons[0])

    // Expanded content should be visible
    expect(screen.getByText('Evidence')).toBeInTheDocument()
    expect(screen.getByText('Risk Explanation')).toBeInTheDocument()
    expect(screen.getByText('Remediation')).toBeInTheDocument()
    expect(screen.getByText(/Enable all block settings/)).toBeInTheDocument()
  })

  it('collapses an expanded row when toggled again', async () => {
    const user = userEvent.setup()
    render(<FindingsTable findings={mockFindings} />)

    const toggleButtons = screen.getAllByRole('button', { name: /toggle finding details/i })
    await user.click(toggleButtons[0])

    // Expanded
    expect(screen.getByText('Evidence')).toBeInTheDocument()

    // Collapse
    await user.click(toggleButtons[0])
    expect(screen.queryByText('Evidence')).not.toBeInTheDocument()
  })

  it('allows multiple rows to be expanded simultaneously', async () => {
    const user = userEvent.setup()
    render(<FindingsTable findings={mockFindings} />)

    const toggleButtons = screen.getAllByRole('button', { name: /toggle finding details/i })
    await user.click(toggleButtons[0])
    await user.click(toggleButtons[1])

    // Both should be expanded — remediation text from both should be visible
    expect(screen.getByText(/Enable all block settings/)).toBeInTheDocument()
    expect(screen.getByText(/Restrict SSH/)).toBeInTheDocument()
  })
})
