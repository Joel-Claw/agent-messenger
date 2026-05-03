import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ConversationList } from '../components/ConversationList';
import type { Agent, Conversation } from '../types';

jest.mock('../services/api', () => ({
  getConversations: jest.fn(),
}));

import * as api from '../services/api';

const mockGetConversations = api.getConversations as jest.MockedFunction<typeof api.getConversations>;

const mockAgents: Agent[] = [
  { id: 'agent-1', name: 'Alpha Bot', model: 'gpt-4', personality: 'helpful', specialty: 'coding', status: 'online' },
  { id: 'agent-2', name: 'Beta Bot', model: 'claude-3', personality: 'friendly', specialty: 'writing', status: 'offline' },
];

const mockConversations: Conversation[] = [
  {
    id: 'conv-1',
    user_id: 'user-1',
    agent_id: 'agent-1',
    created_at: '2026-05-03T00:00:00Z',
    updated_at: '2026-05-03T01:00:00Z',
    last_message: { content: 'Hello from Alpha', sender_type: 'agent', created_at: '2026-05-03T01:00:00Z' },
    unread_count: 3,
  },
  {
    id: 'conv-2',
    user_id: 'user-1',
    agent_id: 'agent-2',
    created_at: '2026-05-02T00:00:00Z',
    updated_at: '2026-05-02T12:00:00Z',
    last_message: { content: 'How can I help?', sender_type: 'agent', created_at: '2026-05-02T12:00:00Z' },
    unread_count: 0,
  },
];

describe('ConversationList', () => {
  const mockOnSelect = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockGetConversations.mockResolvedValue(mockConversations);
  });

  it('renders loading state initially', () => {
    mockGetConversations.mockReturnValueOnce(new Promise(() => {}));
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('renders conversation list after loading', async () => {
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText('Alpha Bot')).toBeInTheDocument();
      expect(screen.getByText('Beta Bot')).toBeInTheDocument();
    });
  });

  it('shows agent name from agents prop', async () => {
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      // Uses agent name from props, not agent_id
      expect(screen.getByText('Alpha Bot')).toBeInTheDocument();
    });
  });

  it('shows last message preview', async () => {
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText(/Hello from Alpha/)).toBeInTheDocument();
    });
  });

  it('shows unread count badge', async () => {
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText('3')).toBeInTheDocument();
    });
  });

  it('calls onSelectConversation when clicked', async () => {
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText('Alpha Bot')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Alpha Bot'));
    expect(mockOnSelect).toHaveBeenCalledWith('conv-1', 'agent-1');
  });

  it('highlights selected conversation', async () => {
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId="conv-1" onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText('Alpha Bot')).toBeInTheDocument();
    });

    const selectedOption = screen.getByRole('option', { name: /Alpha Bot/i });
    expect(selectedOption).toHaveAttribute('aria-selected', 'true');
  });

  it('shows search input when 4+ conversations', async () => {
    const manyConvs: Conversation[] = [
      ...mockConversations,
      {
        id: 'conv-3', user_id: 'user-1', agent_id: 'agent-1', created_at: '2026-05-01T00:00:00Z',
        updated_at: '2026-05-01T01:00:00Z',
        last_message: { content: 'Third message', sender_type: 'agent', created_at: '2026-05-01T01:00:00Z' },
      },
      {
        id: 'conv-4', user_id: 'user-1', agent_id: 'agent-2', created_at: '2026-04-30T00:00:00Z',
        updated_at: '2026-04-30T01:00:00Z',
        last_message: { content: 'Fourth message', sender_type: 'user', created_at: '2026-04-30T01:00:00Z' },
      },
    ];
    mockGetConversations.mockResolvedValueOnce(manyConvs);

    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search conversations...')).toBeInTheDocument();
    });
  });

  it('does not show search input for fewer than 4 conversations', async () => {
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText('Alpha Bot')).toBeInTheDocument();
    });

    expect(screen.queryByPlaceholderText('Search conversations...')).not.toBeInTheDocument();
  });

  it('filters conversations by search query', async () => {
    const manyConvs: Conversation[] = [
      ...mockConversations,
      {
        id: 'conv-3', user_id: 'user-1', agent_id: 'agent-1', created_at: '2026-05-01T00:00:00Z',
        updated_at: '2026-05-01T01:00:00Z',
        last_message: { content: 'Third message', sender_type: 'agent', created_at: '2026-05-01T01:00:00Z' },
      },
      {
        id: 'conv-4', user_id: 'user-1', agent_id: 'agent-2', created_at: '2026-04-30T00:00:00Z',
        updated_at: '2026-04-30T01:00:00Z',
        last_message: { content: 'Fourth message', sender_type: 'user', created_at: '2026-04-30T01:00:00Z' },
      },
    ];
    mockGetConversations.mockResolvedValueOnce(manyConvs);

    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search conversations...')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText('Search conversations...'), { target: { value: 'alpha' } });

    await waitFor(() => {
      // Two conversations with agent-1 (Alpha Bot) should appear
      expect(screen.getAllByText('Alpha Bot')).toHaveLength(2);
    });
    expect(screen.queryByText('Beta Bot')).not.toBeInTheDocument();
  });

  it('shows "You:" prefix for client messages', async () => {
    const clientConv: Conversation[] = [{
      id: 'conv-c', user_id: 'user-1', agent_id: 'agent-1', created_at: '2026-05-03T00:00:00Z',
      updated_at: '2026-05-03T01:00:00Z',
      last_message: { content: 'My message', sender_type: 'client', created_at: '2026-05-03T01:00:00Z' },
    }];
    mockGetConversations.mockResolvedValueOnce(clientConv);

    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByText(/You: My message/)).toBeInTheDocument();
    });
  });

  it('returns null for empty conversation list', async () => {
    mockGetConversations.mockResolvedValueOnce([]);
    const { container } = render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      // Component returns null when no conversations
      expect(container.firstChild).toBeNull();
    });
  });

  it('has proper ARIA roles', async () => {
    render(<ConversationList token="test-token" agents={mockAgents} selectedConversationId={null} onSelectConversation={mockOnSelect} />);

    await waitFor(() => {
      expect(screen.getByRole('listbox', { name: 'Conversations' })).toBeInTheDocument();
    });
  });
});