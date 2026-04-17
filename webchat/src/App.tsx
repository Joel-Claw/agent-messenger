import React, { useState, useCallback } from 'react';
import { AgentList } from './components/AgentList';
import { ChatView } from './components/ChatView';
import { Login } from './components/Login';
import { useWebSocket } from './hooks/useWebSocket';
import { useConversationHistory } from './hooks/useConversationHistory';
import type { ServerMessage, Message } from './types';

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('am_token'));
  const [userId, setUserId] = useState<string | null>(localStorage.getItem('am_user_id'));
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [isTyping, setIsTyping] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);

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
    localStorage.removeItem('am_token');
    localStorage.removeItem('am_user_id');
  };

  const { conversations, activeConversationId, loadHistory, loading: historyLoading } =
    useConversationHistory({
      token,
      selectedAgent,
      connected: false, // will be set below
    });

  const handleMessage = useCallback((msg: ServerMessage) => {
    switch (msg.type) {
      case 'user_message':
        if (msg.conversation_id) {
          setConversationId(msg.conversation_id);
        }
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
        }]);
        break;
      case 'typing':
        setIsTyping(msg.data?.typing as boolean ?? false);
        break;
      case 'conversation_created':
        if (msg.conversation_id) {
          setConversationId(msg.conversation_id);
        }
        break;
      case 'connected':
        console.log('[WebChat] Connected to server');
        break;
      case 'error':
        console.error('[WebChat] Server error:', msg.data);
        break;
    }
  }, []);

  const { connected, send } = useWebSocket({
    token,
    onMessage: handleMessage,
  });

  const handleSelectAgent = (agentId: string) => {
    setSelectedAgent(agentId);
    setMessages([]);
    setConversationId(null);
  };

  const handleSend = (content: string) => {
    if (!selectedAgent) return;

    const localMsg: Message = {
      id: `user-${Date.now()}`,
      conversation_id: conversationId || '',
      sender: 'user',
      content,
      timestamp: new Date().toISOString(),
      type: 'text',
    };
    setMessages(prev => [...prev, localMsg]);

    send({
      type: 'message',
      data: {
        agent_id: selectedAgent,
        content,
        ...(conversationId ? { conversation_id: conversationId } : {}),
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
          <button onClick={handleLogout} style={styles.logoutButton}>
            Sign Out
          </button>
        </div>
        <AgentList
          token={token}
          selectedAgent={selectedAgent}
          onSelectAgent={handleSelectAgent}
        />
      </div>
      <div style={styles.main}>
        {selectedAgent ? (
          <ChatView
            messages={messages}
            onSend={handleSend}
            connected={connected}
            agentName={selectedAgent}
            isTyping={isTyping}
          />
        ) : (
          <div style={styles.empty}>
            <div style={styles.emptyIcon}>💬</div>
            <div style={styles.emptyText}>Select an agent to start chatting</div>
          </div>
        )}
      </div>
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
    width: '240px',
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
  logoutButton: {
    background: 'none',
    border: 'none',
    color: '#8b949e',
    fontSize: '0.75rem',
    cursor: 'pointer',
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