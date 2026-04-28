import React, { useState, useEffect } from 'react';
import { getConversations } from '../services/api';
import type { Conversation, Agent } from '../types';

interface ConversationListProps {
  token: string;
  agents: Agent[];
  selectedConversationId: string | null;
  onSelectConversation: (conversationId: string, agentId: string) => void;
}

export function ConversationList({
  token, agents, selectedConversationId, onSelectConversation,
}: ConversationListProps) {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchConversations = async () => {
      try {
        const data = await getConversations(token);
        setConversations(data || []);
      } catch {
        // Silently ignore
      } finally {
        setLoading(false);
      }
    };
    fetchConversations();
    const interval = setInterval(fetchConversations, 10000);
    return () => clearInterval(interval);
  }, [token]);

  const getAgentName = (agentId: string): string => {
    const agent = agents.find(a => a.id === agentId);
    return agent?.name || agentId;
  };

  const formatTime = (timestamp: string): string => {
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMin = Math.floor(diffMs / 60000);
      if (diffMin < 1) return 'now';
      if (diffMin < 60) return `${diffMin}m`;
      const diffHr = Math.floor(diffMin / 60);
      if (diffHr < 24) return `${diffHr}h`;
      return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return '';
    }
  };

  if (loading) {
    return <div style={styles.loading}>Loading...</div>;
  }

  if (conversations.length === 0) {
    return null;
  }

  return (
    <div style={styles.container}>
      <div style={styles.heading}>Chats</div>
      {conversations.map((conv) => (
        <button
          key={conv.id}
          onClick={() => onSelectConversation(conv.id, conv.agent_id)}
          style={{
            ...styles.convCard,
            ...(selectedConversationId === conv.id ? styles.convSelected : {}),
          }}
        >
          <div style={styles.convHeader}>
            <span style={styles.convAgent}>{getAgentName(conv.agent_id)}</span>
            {conv.last_message && (
              <span style={styles.convTime}>{formatTime(conv.last_message.created_at)}</span>
            )}
          </div>
          {conv.last_message && (
            <div style={styles.convPreview}>
              {conv.last_message.sender_type === 'client' ? 'You: ' : ''}
              {conv.last_message.content.length > 40
                ? conv.last_message.content.slice(0, 38) + '…'
                : conv.last_message.content}
            </div>
          )}
          {(conv.unread_count ?? 0) > 0 && (
            <span style={styles.unreadBadge}>{conv.unread_count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    padding: '0.5rem 1rem',
    overflowY: 'auto',
  },
  heading: {
    fontSize: '0.7rem',
    fontWeight: 600,
    color: '#6e7681',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
    marginBottom: '0.5rem',
  },
  loading: {
    padding: '0.5rem 1rem',
    color: '#8b949e',
    fontSize: '0.75rem',
  },
  convCard: {
    display: 'block',
    width: '100%',
    padding: '0.5rem 0.625rem',
    marginBottom: '0.25rem',
    borderRadius: '6px',
    border: '1px solid transparent',
    backgroundColor: 'transparent',
    color: '#e6edf3',
    cursor: 'pointer',
    textAlign: 'left' as const,
    position: 'relative' as const,
  },
  convSelected: {
    borderColor: '#30363d',
    backgroundColor: '#161b22',
  },
  convHeader: {
    display: 'flex',
    justifyContent: 'space-between' as const,
    alignItems: 'center' as const,
  },
  convAgent: {
    fontWeight: 500,
    fontSize: '0.8125rem',
  },
  convTime: {
    fontSize: '0.625rem',
    color: '#6e7681',
  },
  convPreview: {
    fontSize: '0.75rem',
    color: '#8b949e',
    marginTop: '0.125rem',
    overflow: 'hidden',
    textOverflow: 'ellipsis' as const,
    whiteSpace: 'nowrap' as const,
  },
  unreadBadge: {
    position: 'absolute' as const,
    top: '0.375rem',
    right: '0.5rem',
    backgroundColor: '#0033AA',
    color: '#ffffff',
    fontSize: '0.625rem',
    fontWeight: 600,
    padding: '0.0625rem 0.375rem',
    borderRadius: '8px',
    minWidth: '1rem',
    textAlign: 'center' as const,
  },
};