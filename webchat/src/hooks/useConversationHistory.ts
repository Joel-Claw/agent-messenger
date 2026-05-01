import { useState, useEffect, useCallback } from 'react';
import { getConversations, getMessages } from '../services/api';
import type { Conversation, Message, Reaction } from '../types';

interface UseConversationHistoryOptions {
  token: string | null;
  selectedAgent: string | null;
  connected: boolean;
}

interface UseConversationHistoryReturn {
  conversations: Conversation[];
  messages: Message[];
  activeConversationId: string | null;
  setActiveConversation: (id: string) => void;
  loadHistory: () => Promise<void>;
  loadOlderMessages: () => Promise<void>;
  hasOlderMessages: boolean;
  loading: boolean;
  loadingOlder: boolean;
}

export function useConversationHistory({
  token,
  selectedAgent,
  connected,
}: UseConversationHistoryOptions): UseConversationHistoryReturn {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [hasOlderMessages, setHasOlderMessages] = useState(false);

  const mapMessage = (m: any): Message => ({
    id: m.id as string,
    conversation_id: (m.conversation_id as string) || '',
    sender: (m.sender_type === 'client' ? 'user' : 'agent') as Message['sender'],
    content: (m.content as string) || '',
    timestamp: (m.created_at as string) || (m.timestamp as string) || '',
    type: 'text' as const,
    edited_at: (m.edited_at as string) || undefined,
    is_deleted: (m.is_deleted as boolean) || undefined,
    read_at: (m.read_at as string) || undefined,
    reactions: (m.reactions as Reaction[]) || undefined,
  });

  const loadHistory = useCallback(async () => {
    if (!token || !selectedAgent) return;

    setLoading(true);
    try {
      const convs = await getConversations(token);
      setConversations(convs);

      // Find existing conversation with selected agent
      const existing = convs.find(c => c.agent_id === selectedAgent);
      if (existing) {
        setActiveConversationId(existing.id);
        const rawMsgs: any[] = await getMessages(token, existing.id);
        setMessages(rawMsgs.map(mapMessage));
        // If we got exactly the page limit, there might be more
        setHasOlderMessages(false); // Initial load gets latest messages
      } else {
        setActiveConversationId(null);
        setMessages([]);
        setHasOlderMessages(false);
      }
    } catch (err) {
      console.error('[WebChat] Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  }, [token, selectedAgent]);

  const loadOlderMessages = useCallback(async () => {
    if (!token || !activeConversationId || loadingOlder) return;

    if (messages.length === 0) return;

    // Use the oldest message's timestamp as the cursor
    const oldestTimestamp = messages[0].timestamp;
    if (!oldestTimestamp) return;

    setLoadingOlder(true);
    try {
      const olderMsgs: any[] = await getMessages(token, activeConversationId, {
        before: oldestTimestamp,
        limit: 50,
      });

      if (olderMsgs.length === 0) {
        setHasOlderMessages(false);
        return;
      }

      // Older messages come in chronological order
      const mapped = olderMsgs.map(mapMessage);

      // Prepend older messages, avoiding duplicates
      const existingIds = new Set(messages.map(m => m.id));
      const newMessages = mapped.filter(m => !existingIds.has(m.id));

      if (newMessages.length < olderMsgs.length) {
        // We got fewer unique messages than requested — no more to load
        setHasOlderMessages(false);
      } else {
        setHasOlderMessages(true);
      }

      setMessages(prev => [...newMessages, ...prev]);
    } catch (err) {
      console.error('[WebChat] Failed to load older messages:', err);
    } finally {
      setLoadingOlder(false);
    }
  }, [token, activeConversationId, loadingOlder, messages]);

  // Load history when agent is selected or connection established
  useEffect(() => {
    if (connected && token && selectedAgent) {
      loadHistory();
    }
  }, [connected, token, selectedAgent, loadHistory]);

  const setActiveConversation = useCallback((id: string) => {
    setActiveConversationId(id);
  }, []);

  return {
    conversations,
    messages,
    activeConversationId,
    setActiveConversation,
    loadHistory,
    loadOlderMessages,
    hasOlderMessages,
    loading,
    loadingOlder,
  };
}