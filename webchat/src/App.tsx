import React, { useState, useCallback } from 'react';
import { AgentList } from './components/AgentList';
import { ChatView } from './components/ChatView';
import { ConversationList } from './components/ConversationList';
import { Login } from './components/Login';
import { E2ESettings } from './components/E2ESettings';
import { PushSubscription } from './components/PushSubscription';
import { useWebSocket } from './hooks/useWebSocket';
import { getConversations, getMessages } from './services/api';
import { isE2EInitialized } from './services/e2e';
import type { ServerMessage, Message, Agent, Reaction, Conversation, Attachment } from './types';

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('am_token'));
  const [userId, setUserId] = useState<string | null>(localStorage.getItem('am_user_id'));
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [isTyping, setIsTyping] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [showE2ESettings, setShowE2ESettings] = useState(false);
  const [conversations, setConversations] = useState<Conversation[]>([]);

  const refreshConversations = useCallback(async () => {
    if (!token) return;
    try {
      const convs = await getConversations(token);
      setConversations(convs || []);
    } catch {
      // silently ignore
    }
  }, [token]);

  const loadConversationMessages = useCallback(async (convId: string) => {
    if (!token) return;
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rawMsgs: any[] = await getMessages(token, convId);
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
    } catch {
      // silently ignore
    }
  }, [token]);

  const handleLogin = (newToken: string, newUserId: string) => {
    setToken(newToken);
    setUserId(newUserId);
    localStorage.setItem('am_token', newToken);
    localStorage.setItem('am_user_id', newUserId);
  };

  const handleLogout = () => {
    setToken(null);
    setUserId(null);
    setSelectedAgent(null);
    setMessages([]);
    setConversationId(null);
    setConversations([]);
    localStorage.removeItem('am_token');
    localStorage.removeItem('am_user_id');
  };

  const handleMessage = useCallback((msg: ServerMessage) => {
    switch (msg.type) {
      case 'user_message':
        if (msg.conversation_id) {
          setConversationId(msg.conversation_id);
        }
        // Update local message with server-assigned ID and timestamp
        if (msg.message_id) {
          setMessages(prev => {
            // Find the last user message that still has a local ID
            const idx = [...prev].reverse().findIndex(m => m.sender === 'user' && m.id.startsWith('user-'));
            if (idx !== -1) {
              const realIdx = prev.length - 1 - idx;
              const updated = [...prev];
              updated[realIdx] = {
                ...updated[realIdx],
                id: msg.message_id!,
                timestamp: msg.timestamp || updated[realIdx].timestamp,
                conversation_id: msg.conversation_id || updated[realIdx].conversation_id,
              };
              return updated;
            }
            return prev;
          });
        }
        // Refresh conversation list after new message
        refreshConversations();
        break;
      case 'agent_message':
        setIsTyping(false);
        setMessages(prev => [...prev, {
          id: msg.message_id || `agent-${Date.now()}`,
          conversation_id: msg.conversation_id || '',
          sender: 'agent',
          content: msg.content || '',
          timestamp: msg.timestamp || new Date().toISOString(),
          type: 'text',
          ...(msg.data?.attachments ? { attachments: msg.data.attachments as Attachment[] } : {}),
        }]);
        refreshConversations();
        break;
      case 'typing':
        setIsTyping(msg.data?.typing as boolean ?? false);
        break;
      case 'conversation_created':
        if (msg.conversation_id) {
          setConversationId(msg.conversation_id);
        }
        refreshConversations();
        break;
      case 'reaction_added': {
        const rxA = msg.data as { message_id: string; emoji: string; user_id: string };
        if (rxA?.message_id) {
          setMessages(prev => prev.map(m => {
            if (m.id !== rxA.message_id) return m;
            const reactions = [...(m.reactions || [])];
            const existingIdx = reactions.findIndex(r => r.user_id === rxA.user_id && r.emoji === rxA.emoji);
            if (existingIdx === -1) {
              reactions.push({
                id: `rxn-${Date.now()}`,
                message_id: rxA.message_id,
                user_id: rxA.user_id,
                emoji: rxA.emoji,
                created_at: new Date().toISOString(),
              });
            }
            return { ...m, reactions };
          }));
        }
        break;
      }
      case 'reaction_removed': {
        const rxR = msg.data as { message_id: string; emoji: string; user_id: string };
        if (rxR?.message_id) {
          setMessages(prev => prev.map(m => {
            if (m.id !== rxR.message_id) return m;
            const reactions = (m.reactions || []).filter(r => !(r.user_id === rxR.user_id && r.emoji === rxR.emoji));
            return { ...m, reactions };
          }));
        }
        break;
      }
      case 'message_edited': {
        const edit = msg.data as { message_id: string; content: string; edited_at: string };
        if (edit?.message_id) {
          setMessages(prev => prev.map(m =>
            m.id === edit.message_id ? { ...m, content: edit.content, edited_at: edit.edited_at } : m
          ));
        }
        break;
      }
      case 'message_deleted': {
        const del = msg.data as { message_id: string };
        if (del?.message_id) {
          setMessages(prev => prev.map(m =>
            m.id === del.message_id ? { ...m, content: '[deleted]', is_deleted: true } : m
          ));
        }
        break;
      }
      case 'read_receipt': {
        const receipt = msg.data as { message_id: string; conversation_id: string };
        if (receipt?.message_id) {
          setMessages(prev => prev.map(m =>
            m.id === receipt.message_id ? { ...m, read_at: new Date().toISOString() } : m
          ));
        }
        break;
      }
      case 'presence_update':
        // Handled by AgentList component via polling
        break;
      case 'connected':
        console.log('[WebChat] Connected to server');
        refreshConversations();
        break;
      case 'error':
        console.error('[WebChat] Server error:', msg.data);
        break;
    }
  }, [refreshConversations]);

  const { connected, send } = useWebSocket({
    token,
    onMessage: handleMessage,
  });

  const handleSelectAgent = (agentId: string) => {
    setSelectedAgent(agentId);
    setMessages([]);
    setConversationId(null);
  };

  const handleSelectConversation = (convId: string, agentId: string) => {
    setSelectedAgent(agentId);
    setConversationId(convId);
    loadConversationMessages(convId);
  };

  const handleSend = (content: string, attachmentIds?: string[]) => {
    if (!selectedAgent) return;

    const localId = `user-${Date.now()}`;
    const localMsg: Message = {
      id: localId,
      conversation_id: conversationId || '',
      sender: 'user',
      content,
      timestamp: new Date().toISOString(),
      type: 'text',
      ...(attachmentIds && attachmentIds.length > 0 ? { attachment_ids: attachmentIds } : {}),
    };
    setMessages(prev => [...prev, localMsg]);

    send({
      type: 'message',
      data: {
        agent_id: selectedAgent,
        content,
        ...(conversationId ? { conversation_id: conversationId } : {}),
        ...(attachmentIds && attachmentIds.length > 0 ? { attachment_ids: attachmentIds } : {}),
      },
    });

    setIsTyping(true);
  };

  if (!token || !userId) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div style={styles.app}>
      <div style={styles.sidebar}>
        <div style={styles.sidebarHeader}>
          <span style={styles.logo}>Agent Messenger</span>
          <div style={styles.sidebarActions}>
            <button
              onClick={() => setShowE2ESettings(true)}
              style={styles.e2eButton}
              title="End-to-End Encryption Settings"
            >
              {isE2EInitialized() ? '🔒' : '🔓'}
            </button>
            <button onClick={handleLogout} style={styles.logoutButton}>
              Sign Out
            </button>
          </div>
        </div>
        <AgentList
          token={token}
          selectedAgent={selectedAgent}
          onSelectAgent={handleSelectAgent}
          onAgentsLoaded={setAgents}
        />
        <div style={styles.sidebarSection}>
          <div style={styles.sidebarSectionTitle}>Chats</div>
          <ConversationList
            token={token}
            agents={agents}
            selectedConversationId={conversationId}
            onSelectConversation={handleSelectConversation}
          />
        </div>
        <div style={styles.sidebarSection}>
          <div style={styles.sidebarSectionTitle}>Notifications</div>
          <PushSubscription token={token} />
        </div>
      </div>
      <div style={styles.main}>
        {selectedAgent ? (
          <ChatView
            messages={messages}
            onSend={handleSend}
            connected={connected}
            agentName={selectedAgent}
            isTyping={isTyping}
            token={token}
            userId={userId}
            conversationId={conversationId}
            onMessagesChange={setMessages}
          />
        ) : (
          <div style={styles.empty}>
            <div style={styles.emptyIcon}>💬</div>
            <div style={styles.emptyText}>Select an agent to start chatting</div>
          </div>
        )}
      </div>
      {showE2ESettings && token && (
        <E2ESettings token={token} onClose={() => setShowE2ESettings(false)} />
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  app: {
    display: 'flex',
    height: '100vh',
    backgroundColor: '#0d1117',
    color: '#e6edf3',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  },
  sidebar: {
    display: 'flex',
    flexDirection: 'column' as const,
    width: '280px',
    backgroundColor: '#161b22',
    borderRight: '1px solid #30363d',
  },
  sidebarHeader: {
    display: 'flex',
    justifyContent: 'space-between' as const,
    alignItems: 'center' as const,
    padding: '0.75rem 1rem',
    borderBottom: '1px solid #30363d',
  },
  logo: {
    fontWeight: 600,
    fontSize: '0.875rem',
    color: '#58a6ff',
  },
  sidebarActions: {
    display: 'flex',
    gap: '0.5rem',
    alignItems: 'center' as const,
  },
  e2eButton: {
    background: 'none',
    border: 'none',
    fontSize: '1rem',
    cursor: 'pointer',
    padding: '0.125rem 0.25rem',
    borderRadius: '4px',
  },
  logoutButton: {
    background: 'none',
    border: 'none',
    color: '#8b949e',
    fontSize: '0.75rem',
    cursor: 'pointer',
  },
  sidebarSection: {
    padding: '0.5rem 1rem 0.75rem',
    borderTop: '1px solid #30363d',
  },
  sidebarSectionTitle: {
    fontSize: '0.7rem',
    fontWeight: 600,
    color: '#6e7681',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
    marginBottom: '0.25rem',
  },
  main: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column' as const,
  },
  empty: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column' as const,
    justifyContent: 'center' as const,
    alignItems: 'center' as const,
    color: '#8b949e',
  },
  emptyIcon: {
    fontSize: '3rem',
    marginBottom: '1rem',
  },
  emptyText: {
    fontSize: '1rem',
  },
};

export default App;