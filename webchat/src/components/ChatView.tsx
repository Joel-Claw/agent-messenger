import React, { useState, useRef, useEffect } from 'react';
import type { Message } from '../types';

interface ChatViewProps {
  messages: Message[];
  onSend: (content: string) => void;
  connected: boolean;
  agentName: string;
  isTyping: boolean;
}

export function ChatView({ messages, onSend, connected, agentName, isTyping }: ChatViewProps) {
  const [input, setInput] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || !connected) return;
    onSend(input.trim());
    setInput('');
  };

  const formatTime = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return '';
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <span style={styles.headerName}>{agentName}</span>
        <span style={{
          ...styles.statusText,
          color: connected ? '#3fb950' : '#f85149',
        }}>
          {connected ? '● Connected' : '○ Disconnected'}
        </span>
      </div>

      <div style={styles.messages}>
        {messages.map((msg) => (
          <div
            key={msg.id}
            style={{
              ...styles.messageRow,
              justifyContent: msg.sender === 'user' ? 'flex-end' : 'flex-start',
            }}
          >
            <div style={{
              ...styles.messageBubble,
              ...(msg.sender === 'user' ? styles.userBubble : styles.agentBubble),
            }}>
              <div style={styles.messageText}>{msg.content}</div>
              <div style={styles.messageTime}>{formatTime(msg.timestamp)}</div>
            </div>
          </div>
        ))}
        {isTyping && (
          <div style={{ ...styles.messageRow, justifyContent: 'flex-start' }}>
            <div style={{ ...styles.messageBubble, ...styles.agentBubble }}>
              <div style={styles.typingIndicator}>
                <span style={styles.typingDot}>●</span>
                <span style={styles.typingDot}>●</span>
                <span style={styles.typingDot}>●</span>
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSubmit} style={styles.inputBar}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={connected ? 'Type a message...' : 'Connecting...'}
          disabled={!connected}
          style={styles.input}
        />
        <button
          type="submit"
          disabled={!connected || !input.trim()}
          style={{
            ...styles.sendButton,
            opacity: connected && input.trim() ? 1 : 0.5,
          }}
        >
          Send
        </button>
      </form>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    flex: 1,
    height: '100vh',
    backgroundColor: '#0d1117',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between' as const,
    alignItems: 'center' as const,
    padding: '0.75rem 1rem',
    borderBottom: '1px solid #30363d',
    backgroundColor: '#161b22',
  },
  headerName: {
    fontWeight: 600,
    color: '#e6edf3',
  },
  statusText: {
    fontSize: '0.75rem',
  },
  messages: {
    flex: 1,
    overflowY: 'auto' as const,
    padding: '1rem',
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.5rem',
  },
  messageRow: {
    display: 'flex',
    width: '100%',
  },
  messageBubble: {
    maxWidth: '70%',
    padding: '0.5rem 0.75rem',
    borderRadius: '12px',
    fontSize: '0.875rem',
    lineHeight: 1.5,
  },
  userBubble: {
    backgroundColor: '#0033AA',
    color: '#ffffff',
    borderBottomRightRadius: '4px',
  },
  agentBubble: {
    backgroundColor: '#21262d',
    color: '#e6edf3',
    borderBottomLeftRadius: '4px',
  },
  messageText: {
    whiteSpace: 'pre-wrap' as const,
  },
  messageTime: {
    fontSize: '0.625rem',
    color: '#8b949e',
    marginTop: '0.25rem',
    textAlign: 'right' as const,
  },
  typingIndicator: {
    display: 'flex',
    gap: '0.25rem',
    padding: '0.25rem 0',
  },
  typingDot: {
    fontSize: '0.75rem',
    color: '#8b949e',
    animation: 'blink 1.4s infinite both',
  },
  inputBar: {
    display: 'flex',
    gap: '0.5rem',
    padding: '0.75rem',
    borderTop: '1px solid #30363d',
    backgroundColor: '#161b22',
  },
  input: {
    flex: 1,
    padding: '0.75rem',
    borderRadius: '6px',
    border: '1px solid #30363d',
    backgroundColor: '#0d1117',
    color: '#e6edf3',
    fontSize: '0.875rem',
  },
  sendButton: {
    padding: '0.75rem 1.5rem',
    borderRadius: '6px',
    border: 'none',
    backgroundColor: '#0033AA',
    color: '#ffffff',
    fontWeight: 600,
    cursor: 'pointer',
    fontSize: '0.875rem',
  },
};