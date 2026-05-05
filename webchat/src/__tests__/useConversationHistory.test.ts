import { renderHook, waitFor, act } from '@testing-library/react';
import { useConversationHistory } from '../hooks/useConversationHistory';

// Mock API
jest.mock('../services/api', () => ({
  getConversations: jest.fn(),
  getMessages: jest.fn(),
}));

import * as api from '../services/api';

const mockGetConversations = api.getConversations as jest.MockedFunction<typeof api.getConversations>;
const mockGetMessages = api.getMessages as jest.MockedFunction<typeof api.getMessages>;

describe('useConversationHistory', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns empty state when no token or agent', () => {
    const { result } = renderHook(() => useConversationHistory({
      token: null,
      selectedAgent: null,
      connected: false,
    }));

    expect(result.current.conversations).toEqual([]);
    expect(result.current.messages).toEqual([]);
    expect(result.current.activeConversationId).toBeNull();
    expect(result.current.loading).toBe(false);
  });

  it('loads conversations and messages on connect', async () => {
    const conversations = [
      { id: 'conv-1', user_id: 'u1', agent_id: 'agent-1', created_at: '', updated_at: '' },
    ];
    const mockMessages = [
      { id: 'm1', conversation_id: 'conv-1', sender: 'agent' as const, content: 'Hello', timestamp: '2026-05-03T10:00:00Z', type: 'text' as const },
      { id: 'm2', conversation_id: 'conv-1', sender: 'user' as const, content: 'Hi', timestamp: '2026-05-03T10:01:00Z', type: 'text' as const },
    ];

    mockGetConversations.mockResolvedValueOnce(conversations);
    mockGetMessages.mockResolvedValueOnce(mockMessages);

    const { result } = renderHook(() => useConversationHistory({
      token: 'test-token',
      selectedAgent: 'agent-1',
      connected: true,
    }));

    await waitFor(() => {
      expect(result.current.conversations).toEqual(conversations);
      expect(result.current.messages.length).toBe(2);
      expect(result.current.activeConversationId).toBe('conv-1');
    });

    expect(mockGetConversations).toHaveBeenCalledWith('test-token');
    expect(mockGetMessages).toHaveBeenCalledWith('test-token', 'conv-1');
  });

  it('maps sender_type to sender correctly', async () => {
    const conversations = [
      { id: 'conv-1', user_id: 'u1', agent_id: 'agent-1', created_at: '', updated_at: '' },
    ];
    const mockMessages = [
      { id: 'm1', conversation_id: 'conv-1', sender_type: 'client', content: 'User msg', created_at: '2026-05-03T10:00:00Z', type: 'text' as const },
      { id: 'm2', conversation_id: 'conv-1', sender_type: 'agent', content: 'Agent msg', created_at: '2026-05-03T10:01:00Z', type: 'text' as const },
    ];

    mockGetConversations.mockResolvedValueOnce(conversations);
    mockGetMessages.mockResolvedValueOnce(mockMessages);

    const { result } = renderHook(() => useConversationHistory({
      token: 'test-token',
      selectedAgent: 'agent-1',
      connected: true,
    }));

    await waitFor(() => {
      expect(result.current.messages.length).toBe(2);
    });

    expect(result.current.messages[0].sender).toBe('user');
    expect(result.current.messages[1].sender).toBe('agent');
  });

  it('sets empty state when no existing conversation for agent', async () => {
    mockGetConversations.mockResolvedValueOnce([]);

    const { result } = renderHook(() => useConversationHistory({
      token: 'test-token',
      selectedAgent: 'agent-1',
      connected: true,
    }));

    await waitFor(() => {
      expect(result.current.activeConversationId).toBeNull();
      expect(result.current.messages).toEqual([]);
    });
  });

  it('sets loading state during fetch', async () => {
    let resolveConvs: (v: any) => void;
    mockGetConversations.mockImplementationOnce(() => new Promise(r => { resolveConvs = r; }));

    const { result } = renderHook(() => useConversationHistory({
      token: 'test-token',
      selectedAgent: 'agent-1',
      connected: true,
    }));

    // Should be loading
    await waitFor(() => {
      expect(result.current.loading).toBe(true);
    });

    // Resolve
    await act(async () => {
      resolveConvs!([]);
    });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
  });

  it('loads older messages with cursor pagination', async () => {
    const conversations = [
      { id: 'conv-1', user_id: 'u1', agent_id: 'agent-1', created_at: '', updated_at: '' },
    ];
    const recentMessages = [
      { id: 'm3', conversation_id: 'conv-1', sender: 'agent' as const, content: 'Recent', timestamp: '2026-05-03T10:02:00Z', type: 'text' as const },
    ];
    const olderMessages = [
      { id: 'm1', conversation_id: 'conv-1', sender: 'agent' as const, content: 'Old', timestamp: '2026-05-03T10:00:00Z', type: 'text' as const },
      { id: 'm2', conversation_id: 'conv-1', sender: 'user' as const, content: 'Older', timestamp: '2026-05-03T10:01:00Z', type: 'text' as const },
    ];

    mockGetConversations.mockResolvedValueOnce(conversations);
    mockGetMessages.mockResolvedValueOnce(recentMessages);
    mockGetMessages.mockResolvedValueOnce(olderMessages);

    const { result } = renderHook(() => useConversationHistory({
      token: 'test-token',
      selectedAgent: 'agent-1',
      connected: true,
    }));

    await waitFor(() => {
      expect(result.current.messages.length).toBe(1);
    });

    // Set hasOlderMessages to true for test
    // Now load older
    await act(async () => {
      await result.current.loadOlderMessages();
    });

    await waitFor(() => {
      expect(result.current.messages.length).toBe(3);
    });

    expect(mockGetMessages).toHaveBeenCalledWith('test-token', 'conv-1', {
      before: '2026-05-03T10:02:00Z',
      limit: 50,
    });
  });

  it('handles API errors gracefully', async () => {
    mockGetConversations.mockRejectedValueOnce(new Error('Network error'));

    const { result } = renderHook(() => useConversationHistory({
      token: 'test-token',
      selectedAgent: 'agent-1',
      connected: true,
    }));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      // Should not crash, state remains empty
      expect(result.current.conversations).toEqual([]);
    });
  });

  it('reloads history when selectedAgent changes', async () => {
    mockGetConversations.mockResolvedValueOnce([]);
    mockGetConversations.mockResolvedValueOnce([
      { id: 'conv-2', user_id: 'u1', agent_id: 'agent-2', created_at: '', updated_at: '' },
    ]);
    mockGetMessages.mockResolvedValueOnce([
      { id: 'm1', conversation_id: 'conv-2', sender: 'agent' as const, content: 'Hello from 2', timestamp: '2026-05-03T10:00:00Z', type: 'text' as const },
    ]);

    const { result, rerender } = renderHook(
      ({ agent }) => useConversationHistory({
        token: 'test-token',
        selectedAgent: agent,
        connected: true,
      }),
      { initialProps: { agent: 'agent-1' } }
    );

    await waitFor(() => {
      expect(mockGetConversations).toHaveBeenCalledTimes(1);
    });

    // Change agent
    rerender({ agent: 'agent-2' });

    await waitFor(() => {
      expect(mockGetConversations).toHaveBeenCalledTimes(2);
    });
  });
});