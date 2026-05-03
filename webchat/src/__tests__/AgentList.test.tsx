import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { AgentList } from '../components/AgentList';
import type { Agent, AgentPresence } from '../types';

// Mock the API module
jest.mock('../services/api', () => ({
  getAgents: jest.fn(),
  getPresence: jest.fn(),
}));

import * as api from '../services/api';

const mockGetAgents = api.getAgents as jest.MockedFunction<typeof api.getAgents>;
const mockGetPresence = api.getPresence as jest.MockedFunction<typeof api.getPresence>;

const mockAgents: Agent[] = [
  { id: 'agent-1', name: 'Alpha', model: 'gpt-4', personality: 'helpful', specialty: 'coding', status: 'online' },
  { id: 'agent-2', name: 'Beta', model: 'claude-3', personality: 'friendly', specialty: 'writing', status: 'offline' },
  { id: 'agent-3', name: 'Gamma', model: 'llama', personality: 'concise', specialty: 'analysis', status: 'busy' },
];

const mockPresence: AgentPresence[] = [
  { id: 'agent-1', name: 'Alpha', online: true, status: 'online' },
  { id: 'agent-2', name: 'Beta', online: false, status: 'offline', last_seen: '2026-05-02T20:00:00Z' },
];

describe('AgentList', () => {
  const mockOnSelectAgent = jest.fn();
  const mockOnAgentsLoaded = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockGetAgents.mockResolvedValue(mockAgents);
    mockGetPresence.mockResolvedValue(mockPresence);
  });

  it('renders loading state initially', () => {
    mockGetAgents.mockReturnValueOnce(new Promise(() => {}));
    render(<AgentList token="test-token" selectedAgent={null} onSelectAgent={mockOnSelectAgent} />);
    expect(screen.getByText('Loading agents...')).toBeInTheDocument();
  });

  it('renders agent list after loading', async () => {
    render(<AgentList token="test-token" selectedAgent={null} onSelectAgent={mockOnSelectAgent} onAgentsLoaded={mockOnAgentsLoaded} />);

    await waitFor(() => {
      expect(screen.getByText('Alpha')).toBeInTheDocument();
      expect(screen.getByText('Beta')).toBeInTheDocument();
      expect(screen.getByText('Gamma')).toBeInTheDocument();
    });

    expect(mockOnAgentsLoaded).toHaveBeenCalledWith(mockAgents);
  });

  it('shows agent specialties', async () => {
    render(<AgentList token="test-token" selectedAgent={null} onSelectAgent={mockOnSelectAgent} />);
    await waitFor(() => {
      expect(screen.getByText('coding')).toBeInTheDocument();
      expect(screen.getByText('writing')).toBeInTheDocument();
      expect(screen.getByText('analysis')).toBeInTheDocument();
    });
  });

  it('calls onSelectAgent when agent is clicked', async () => {
    render(<AgentList token="test-token" selectedAgent={null} onSelectAgent={mockOnSelectAgent} />);
    await waitFor(() => {
      expect(screen.getByText('Alpha')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('Alpha'));
    expect(mockOnSelectAgent).toHaveBeenCalledWith('agent-1');
  });

  it('highlights selected agent', async () => {
    render(<AgentList token="test-token" selectedAgent="agent-1" onSelectAgent={mockOnSelectAgent} />);
    await waitFor(() => {
      expect(screen.getByText('Alpha')).toBeInTheDocument();
    });
    const selectedButton = screen.getByRole('option', { name: /Alpha.*online/i });
    expect(selectedButton).toHaveAttribute('aria-selected', 'true');
  });

  it('shows error state when fetch fails', async () => {
    mockGetAgents.mockRejectedValueOnce(new Error('Network error'));
    render(<AgentList token="test-token" selectedAgent={null} onSelectAgent={mockOnSelectAgent} />);
    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });
  });

  it('shows empty state when no agents', async () => {
    mockGetAgents.mockResolvedValueOnce([]);
    render(<AgentList token="test-token" selectedAgent={null} onSelectAgent={mockOnSelectAgent} />);
    await waitFor(() => {
      expect(screen.getByText('No agents online')).toBeInTheDocument();
    });
  });

  it('uses presence data for online status', async () => {
    render(<AgentList token="test-token" selectedAgent={null} onSelectAgent={mockOnSelectAgent} />);
    await waitFor(() => {
      expect(screen.getByText('Alpha')).toBeInTheDocument();
    });
    // Alpha is online in presence data
    expect(screen.getByLabelText(/Alpha.*online/i)).toBeInTheDocument();
    // Beta is offline in presence data
    expect(screen.getByLabelText(/Beta.*offline/i)).toBeInTheDocument();
  });

  it('has proper ARIA roles', async () => {
    render(<AgentList token="test-token" selectedAgent={null} onSelectAgent={mockOnSelectAgent} />);
    await waitFor(() => {
      expect(screen.getByRole('listbox', { name: 'Available agents' })).toBeInTheDocument();
    });
  });
});

