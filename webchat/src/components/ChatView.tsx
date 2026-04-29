import React, { useState, useRef, useEffect, useCallback } from 'react';
import { AttachmentUpload } from './AttachmentUpload';
import { AttachmentPreview } from './AttachmentPreview';
import { toggleReaction, editMessage, deleteMessage, markConversationRead } from '../services/api';
import { playNotificationSound, showDesktopNotification } from '../services/notify';
import type { Message, UploadResult } from '../types';
import { isE2EInitialized } from '../services/e2e';

const QUICK_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];

interface ChatViewProps {
  messages: Message[];
  onSend: (content: string, attachmentIds?: string[]) => void;
  connected: boolean;
  agentName: string;
  isTyping: boolean;
  token: string;
  userId: string | null;
  conversationId: string | null;
  onMessagesChange: (msgs: Message[]) => void;
}

interface ContextMenuState {
  visible: boolean;
  x: number;
  y: number;
  messageId: string;
  sender: 'user' | 'agent';
  isDeleted: boolean;
}

export function ChatView({
  messages, onSend, connected, agentName, isTyping, token, userId, conversationId, onMessagesChange
}: ChatViewProps) {
  const [input, setInput] = useState('');
  const [pendingAttachments, setPendingAttachments] = useState<UploadResult[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [droppedFiles, setDroppedFiles] = useState<File[] | null>(null);
  const [e2eEnabled, setE2eEnabled] = useState(false);
  const [editingMessageId, setEditingMessageId] = useState<string | null>(null);
  const [editContent, setEditContent] = useState('');
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [emojiPickerMsgId, setEmojiPickerMsgId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const isNearBottomRef = useRef(true);

  // Track whether user is near bottom of the chat
  const handleScroll = useCallback(() => {
    const el = dropAreaRef.current;
    if (el) {
      const threshold = 80;
      isNearBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < threshold;
    }
  }, []);
  const dropAreaRef = useRef<HTMLDivElement>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);
  const emojiPickerRef = useRef<HTMLDivElement>(null);

  // Mark conversation as read when messages come in
  useEffect(() => {
    if (conversationId && token && messages.length > 0) {
      markConversationRead(token, conversationId).catch(() => {});
    }
  }, [messages.length, conversationId, token]);

  // Close context menu on click outside
  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setContextMenu(null);
      }
      if (emojiPickerRef.current && !emojiPickerRef.current.contains(e.target as Node)) {
        setEmojiPickerMsgId(null);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  useEffect(() => {
    // Only auto-scroll if user is near the bottom
    if (isNearBottomRef.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isTyping]);

  const handleAttachmentUploaded = (result: UploadResult) => {
    setPendingAttachments(prev => [...prev, result]);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if ((!input.trim() && pendingAttachments.length === 0) || !connected) return;

    const attachmentIds = pendingAttachments.map(a => a.id);
    onSend(input.trim() || '📎', attachmentIds.length > 0 ? attachmentIds : undefined);
    setInput('');
    setPendingAttachments([]);
    isNearBottomRef.current = true; // Force scroll after sending
  };

  const handleRemovePendingAttachment = (id: string) => {
    setPendingAttachments(prev => prev.filter(a => a.id !== id));
  };

  const handleContextMenu = (e: React.MouseEvent, msg: Message) => {
    e.preventDefault();
    setContextMenu({
      visible: true,
      x: e.clientX,
      y: e.clientY,
      messageId: msg.id,
      sender: msg.sender,
      isDeleted: !!msg.is_deleted,
    });
    setEmojiPickerMsgId(null);
  };

  const handleReact = async (messageId: string, emoji: string) => {
    setEmojiPickerMsgId(null);
    setContextMenu(null);
    try {
      await toggleReaction(token, messageId, emoji);
      // Reaction state updates come via WebSocket (reaction_added/reaction_removed)
    } catch (err) {
      console.error('Reaction failed:', err);
    }
  };

  const handleEdit = (messageId: string, currentContent: string) => {
    setContextMenu(null);
    setEditingMessageId(messageId);
    setEditContent(currentContent);
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingMessageId || !editContent.trim()) return;
    try {
      await editMessage(token, editingMessageId, editContent.trim());
      // Edit state updates come via WebSocket (message_edited)
      setEditingMessageId(null);
      setEditContent('');
    } catch (err) {
      console.error('Edit failed:', err);
    }
  };

  const handleEditCancel = () => {
    setEditingMessageId(null);
    setEditContent('');
  };

  const handleDelete = async (messageId: string) => {
    setContextMenu(null);
    try {
      await deleteMessage(token, messageId);
      // Delete state updates come via WebSocket (message_deleted)
    } catch (err) {
      console.error('Delete failed:', err);
    }
  };

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (dropAreaRef.current && !dropAreaRef.current.contains(e.relatedTarget as Node)) {
      setDragOver(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    if (!connected) return;
    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;
    setDroppedFiles(Array.from(files));
  }, [connected]);

  const handleDropsConsumed = useCallback(() => {
    setDroppedFiles(null);
  }, []);

  const formatTime = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return '';
    }
  };

  const formatDateSeparator = (timestamp: string): string | null => {
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const messageDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());
      const diffDays = Math.floor((today.getTime() - messageDate.getTime()) / (86400000));
      if (diffDays === 0) return 'Today';
      if (diffDays === 1) return 'Yesterday';
      return date.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
    } catch {
      return null;
    }
  };

  const shouldShowDateSeparator = (messages: Message[], index: number): string | null => {
    if (index === 0) {
      return formatDateSeparator(messages[0].timestamp);
    }
    const prevDate = new Date(messages[index - 1].timestamp).toDateString();
    const currDate = new Date(messages[index].timestamp).toDateString();
    if (prevDate !== currDate) {
      return formatDateSeparator(messages[index].timestamp);
    }
    return null;
  };

  const groupReactions = (reactions: Message['reactions']) => {
    if (!reactions || reactions.length === 0) return [];
    const map = new Map<string, { emoji: string; count: number; includesMe: boolean }>();
    for (const r of reactions) {
      const existing = map.get(r.emoji);
      if (existing) {
        existing.count++;
        if (r.user_id === userId) existing.includesMe = true;
      } else {
        map.set(r.emoji, { emoji: r.emoji, count: 1, includesMe: r.user_id === userId });
      }
    }
    return Array.from(map.values());
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <span style={styles.headerName}>{agentName}</span>
        <div style={styles.headerRight}>
          {isE2EInitialized() && (
            <button
              type="button"
              onClick={() => setE2eEnabled(v => !v)}
              style={{
                ...styles.e2eToggle,
                backgroundColor: e2eEnabled ? 'rgba(35, 134, 54, 0.2)' : 'transparent',
                borderColor: e2eEnabled ? '#3fb950' : '#30363d',
                color: e2eEnabled ? '#3fb950' : '#8b949e',
              }}
              title={e2eEnabled ? 'E2E encryption ON' : 'E2E encryption OFF (click to enable)'}
            >
              {e2eEnabled ? '🔒' : '🔓'}
            </button>
          )}
          <span style={{
            ...styles.statusText,
            color: connected ? '#3fb950' : '#f85149',
          }}>
            {connected ? '● Connected' : '○ Disconnected'}
          </span>
        </div>
      </div>

      <div
        ref={dropAreaRef}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onScroll={handleScroll}
        style={{
          ...styles.messages,
          ...(dragOver ? styles.dragOver : {}),
        }}
      >
        {dragOver && (
          <div style={styles.dropOverlay}>
            <div style={styles.dropIcon}>📎</div>
            <div style={styles.dropText}>Drop files to attach</div>
          </div>
        )}
        {messages.map((msg, idx) => {
          const reactionGroups = groupReactions(msg.reactions);
          const isEditing = editingMessageId === msg.id;
          const dateSeparator = shouldShowDateSeparator(messages, idx);

          return (
            <React.Fragment key={msg.id}>
              {dateSeparator && (
                <div style={styles.dateSeparator}>
                  <span style={styles.dateSeparatorText}>{dateSeparator}</span>
                </div>
              )}
              <div
                style={{
                  ...styles.messageRow,
                  justifyContent: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                }}
              >
              <div
                style={{
                  ...styles.messageBubble,
                  ...(msg.sender === 'user' ? styles.userBubble : styles.agentBubble),
                  ...(msg.is_deleted ? styles.deletedBubble : {}),
                }}
                onContextMenu={(e) => handleContextMenu(e, msg)}
              >
                {msg.attachments && msg.attachments.length > 0 && (
                  <div style={styles.attachmentsContainer}>
                    {msg.attachments.map(att => (
                      <AttachmentPreview
                        key={att.id}
                        attachment={att}
                        token={token}
                      />
                    ))}
                  </div>
                )}
                {isEditing ? (
                  <form onSubmit={handleEditSubmit} style={styles.editForm}>
                    <input
                      type="text"
                      value={editContent}
                      onChange={(e) => setEditContent(e.target.value)}
                      style={styles.editInput}
                      autoFocus
                    />
                    <div style={styles.editActions}>
                      <button type="submit" style={styles.editSave}>Save</button>
                      <button type="button" onClick={handleEditCancel} style={styles.editCancel}>Cancel</button>
                    </div>
                  </form>
                ) : (
                  <>
                    {msg.content && msg.content !== '📎' && (
                      <div style={styles.messageText}>
                        {msg.is_deleted ? (
                          <span style={styles.deletedText}>{msg.content}</span>
                        ) : (
                          msg.content
                        )}
                      </div>
                    )}
                    <div style={styles.messageMeta}>
                      {msg.edited_at && !msg.is_deleted && (
                        <span style={styles.editedLabel}>edited</span>
                      )}
                      {msg.sender === 'user' && !msg.is_deleted && (
                        <span style={styles.readReceipt}>
                          {msg.read_at ? '✓✓' : '✓'}
                        </span>
                      )}
                      <span style={styles.messageTime}>{formatTime(msg.timestamp)}</span>
                    </div>
                  </>
                )}
                {!isEditing && !msg.is_deleted && reactionGroups.length > 0 && (
                  <div style={styles.reactionsBar}>
                    {reactionGroups.map(g => (
                      <button
                        key={g.emoji}
                        onClick={() => handleReact(msg.id, g.emoji)}
                        style={{
                          ...styles.reactionChip,
                          ...(g.includesMe ? styles.reactionChipActive : {}),
                        }}
                        title={g.includesMe ? 'Click to remove' : 'Click to react'}
                      >
                        {g.emoji} {g.count}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              {/* Quick-react button on hover */}
              {!msg.is_deleted && !isEditing && (
                <button
                  onClick={() => setEmojiPickerMsgId(emojiPickerMsgId === msg.id ? null : msg.id)}
                  style={styles.reactButton}
                  title="React"
                >
                  😊
                </button>
              )}
              {emojiPickerMsgId === msg.id && (
                <div ref={emojiPickerRef} style={styles.emojiPicker}>
                  {QUICK_EMOJIS.map(emoji => (
                    <button
                      key={emoji}
                      onClick={() => handleReact(msg.id, emoji)}
                      style={styles.emojiButton}
                    >
                      {emoji}
                    </button>
                  ))}
                </div>
              )}
            </div>
            </React.Fragment>
          );
        })}
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

      {pendingAttachments.length > 0 && (
        <div style={styles.pendingBar}>
          {pendingAttachments.map(att => (
            <div key={att.id} style={styles.pendingChip}>
              <span style={styles.pendingChipIcon}>
                {att.content_type.startsWith('image/') ? '🖼' : '📎'}
              </span>
              <span style={styles.pendingChipName}>
                {att.filename.length > 12 ? att.filename.slice(0, 10) + '…' : att.filename}
              </span>
              <button
                type="button"
                onClick={() => handleRemovePendingAttachment(att.id)}
                style={styles.pendingChipRemove}
                aria-label="Remove attachment"
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}

      <form onSubmit={handleSubmit} style={styles.inputBar}>
        <AttachmentUpload
          token={token}
          onUploaded={handleAttachmentUploaded}
          disabled={!connected}
          droppedFiles={droppedFiles}
          onDropsConsumed={handleDropsConsumed}
        />
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
          disabled={!connected || (!input.trim() && pendingAttachments.length === 0)}
          style={{
            ...styles.sendButton,
            opacity: connected && (input.trim() || pendingAttachments.length > 0) ? 1 : 0.5,
          }}
        >
          Send
        </button>
      </form>

      {/* Context Menu */}
      {contextMenu && (
        <div
          ref={contextMenuRef}
          style={{
            ...styles.contextMenu,
            left: contextMenu.x,
            top: contextMenu.y,
          }}
        >
          {!contextMenu.isDeleted && (
            <>
              <button
                onClick={() => {
                  setEmojiPickerMsgId(contextMenu.messageId);
                  setContextMenu(null);
                }}
                style={styles.contextMenuItem}
              >
                😊 React
              </button>
              {contextMenu.sender === 'user' && (
                <>
                  <button
                    onClick={() => {
                      const msg = messages.find(m => m.id === contextMenu.messageId);
                      if (msg) handleEdit(contextMenu.messageId, msg.content);
                    }}
                    style={styles.contextMenuItem}
                  >
                    ✏️ Edit
                  </button>
                  <button
                    onClick={() => handleDelete(contextMenu.messageId)}
                    style={{ ...styles.contextMenuItem, color: '#f85149' }}
                  >
                    🗑️ Delete
                  </button>
                </>
              )}
              <button
                onClick={() => {
                  navigator.clipboard.writeText(
                    messages.find(m => m.id === contextMenu.messageId)?.content || ''
                  );
                  setContextMenu(null);
                }}
                style={styles.contextMenuItem}
              >
                📋 Copy
              </button>
            </>
          )}
        </div>
      )}
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
  headerRight: {
    display: 'flex',
    alignItems: 'center' as const,
    gap: '0.75rem',
  },
  e2eToggle: {
    border: '1px solid',
    borderRadius: '4px',
    background: 'none',
    cursor: 'pointer',
    fontSize: '0.875rem',
    padding: '0.125rem 0.375rem',
    transition: 'all 0.15s',
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
    position: 'relative' as const,
  },
  dragOver: {
    backgroundColor: 'rgba(88, 166, 255, 0.05)',
  },
  dropOverlay: {
    position: 'absolute' as const,
    inset: 0,
    display: 'flex',
    flexDirection: 'column' as const,
    justifyContent: 'center' as const,
    alignItems: 'center' as const,
    backgroundColor: 'rgba(13, 17, 23, 0.85)',
    borderRadius: '8px',
    zIndex: 10,
    pointerEvents: 'none' as const,
  },
  dropIcon: {
    fontSize: '2.5rem',
    marginBottom: '0.5rem',
  },
  dropText: {
    fontSize: '1rem',
    color: '#58a6ff',
    fontWeight: 500,
  },
  messageRow: {
    display: 'flex',
    width: '100%',
    alignItems: 'flex-start' as const,
    gap: '0.25rem',
    position: 'relative' as const,
  },
  dateSeparator: {
    display: 'flex',
    justifyContent: 'center' as const,
    alignItems: 'center' as const,
    margin: '0.75rem 0',
    gap: '0.75rem',
  },
  dateSeparatorText: {
    fontSize: '0.7rem',
    color: '#6e7681',
    backgroundColor: '#0d1117',
    padding: '0.125rem 0.5rem',
    borderRadius: '8px',
    border: '1px solid #21262d',
  },
  messageBubble: {
    maxWidth: '70%',
    padding: '0.5rem 0.75rem',
    borderRadius: '12px',
    fontSize: '0.875rem',
    lineHeight: 1.5,
    position: 'relative' as const,
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
  deletedBubble: {
    opacity: 0.5,
  },
  deletedText: {
    fontStyle: 'italic' as const,
    color: '#8b949e',
  },
  attachmentsContainer: {
    marginBottom: '0.25rem',
  },
  messageText: {
    whiteSpace: 'pre-wrap' as const,
  },
  messageMeta: {
    display: 'flex',
    alignItems: 'center' as const,
    gap: '0.375rem',
    justifyContent: 'flex-end' as const,
    marginTop: '0.25rem',
  },
  editedLabel: {
    fontSize: '0.6rem',
    color: '#8b949e',
    fontStyle: 'italic' as const,
  },
  readReceipt: {
    fontSize: '0.65rem',
    color: '#8b949e',
  },
  messageTime: {
    fontSize: '0.625rem',
    color: '#8b949e',
  },
  reactionsBar: {
    display: 'flex',
    gap: '0.25rem',
    marginTop: '0.25rem',
    flexWrap: 'wrap' as const,
  },
  reactionChip: {
    display: 'inline-flex',
    alignItems: 'center' as const,
    gap: '0.125rem',
    padding: '0.0625rem 0.375rem',
    borderRadius: '10px',
    border: '1px solid #30363d',
    backgroundColor: '#161b22',
    color: '#e6edf3',
    fontSize: '0.7rem',
    cursor: 'pointer',
    lineHeight: 1.4,
  },
  reactionChipActive: {
    borderColor: '#58a6ff',
    backgroundColor: 'rgba(88, 166, 255, 0.1)',
  },
  reactButton: {
    background: 'none',
    border: 'none',
    fontSize: '0.75rem',
    cursor: 'pointer',
    padding: '0.125rem',
    opacity: 0.3,
    transition: 'opacity 0.15s',
    alignSelf: 'center' as const,
  },
  emojiPicker: {
    position: 'absolute' as const,
    display: 'flex',
    gap: '0.125rem',
    padding: '0.25rem',
    backgroundColor: '#21262d',
    border: '1px solid #30363d',
    borderRadius: '8px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
    zIndex: 20,
  },
  emojiButton: {
    background: 'none',
    border: 'none',
    fontSize: '1rem',
    cursor: 'pointer',
    padding: '0.25rem',
    borderRadius: '4px',
    transition: 'background 0.1s',
  },
  editForm: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.375rem',
  },
  editInput: {
    padding: '0.375rem 0.5rem',
    borderRadius: '4px',
    border: '1px solid #58a6ff',
    backgroundColor: '#0d1117',
    color: '#e6edf3',
    fontSize: '0.875rem',
  },
  editActions: {
    display: 'flex',
    gap: '0.375rem',
  },
  editSave: {
    padding: '0.25rem 0.75rem',
    borderRadius: '4px',
    border: 'none',
    backgroundColor: '#238636',
    color: '#ffffff',
    cursor: 'pointer',
    fontSize: '0.75rem',
    fontWeight: 500,
  },
  editCancel: {
    padding: '0.25rem 0.75rem',
    borderRadius: '4px',
    border: '1px solid #30363d',
    backgroundColor: 'transparent',
    color: '#8b949e',
    cursor: 'pointer',
    fontSize: '0.75rem',
  },
  contextMenu: {
    position: 'fixed' as const,
    backgroundColor: '#21262d',
    border: '1px solid #30363d',
    borderRadius: '8px',
    padding: '0.25rem',
    boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
    zIndex: 100,
    minWidth: '140px',
  },
  contextMenuItem: {
    display: 'block',
    width: '100%',
    padding: '0.5rem 0.75rem',
    border: 'none',
    background: 'none',
    color: '#e6edf3',
    fontSize: '0.8rem',
    cursor: 'pointer',
    textAlign: 'left' as const,
    borderRadius: '4px',
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
  pendingBar: {
    display: 'flex',
    gap: '0.375rem',
    padding: '0.5rem 0.75rem',
    borderTop: '1px solid #30363d',
    backgroundColor: '#161b22',
    flexWrap: 'wrap' as const,
  },
  pendingChip: {
    display: 'flex',
    alignItems: 'center' as const,
    gap: '0.25rem',
    padding: '0.25rem 0.5rem',
    backgroundColor: '#21262d',
    borderRadius: '12px',
    fontSize: '0.75rem',
    color: '#e6edf3',
    border: '1px solid #30363d',
  },
  pendingChipIcon: {
    fontSize: '0.75rem',
  },
  pendingChipName: {
    maxWidth: '80px',
    overflow: 'hidden',
    textOverflow: 'ellipsis' as const,
    whiteSpace: 'nowrap' as const,
  },
  pendingChipRemove: {
    background: 'none',
    border: 'none',
    color: '#8b949e',
    cursor: 'pointer',
    fontSize: '0.875rem',
    padding: '0 0.125rem',
    lineHeight: 1,
  },
  inputBar: {
    display: 'flex',
    alignItems: 'center' as const,
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