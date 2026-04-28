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
  loading: boolean;
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
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const rawMsgs: any[] = await getMessages(token, existing.id);
        setMessages(rawMsgs.map((m: any): Message => ({
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
        })));
      } else {
        setActiveConversationId(null);
        setMessages([]);
      }
    } catch (err) {
      console.error('[WebChat] Failed to load history:', err);
    } finally {
      setLoading(false);
    }
  }, [token, selectedAgent]);

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
    loading,
  };
}