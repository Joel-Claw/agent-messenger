// Auto-mock the api module - this creates jest.fn() stubs for all exports
jest.mock('../services/api');

jest.mock('../services/e2e', () => ({
  isE2EInitialized: jest.fn(() => false),
}));

jest.mock('../components/AttachmentUpload', () => ({
  AttachmentUpload: ({ onUploaded, disabled }: { onUploaded: (r: any) => void; disabled: boolean }) => (
    <button
      data-testid="attachment-upload"
      disabled={disabled}
      onClick={() => onUploaded({ id: 'att-1', filename: 'test.png', content_type: 'image/png', size: 1024, sha256: 'abc', url: '/files/att-1', created_at: '2026-05-03T00:00:00Z' })}
    >
      Upload
    </button>
  ),
}));

jest.mock('../components/AttachmentPreview', () => ({
  AttachmentPreview: ({ attachment }: { attachment: any }) => (
    <div data-testid={`attachment-preview-${attachment.id}`}>{attachment.filename}</div>
  ),
}));

import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ChatView } from '../components/ChatView';
import type { Message } from '../types';
import * as api from '../services/api';

// JSDOM doesn't implement scrollIntoView
Element.prototype.scrollIntoView = jest.fn();
// JSDOM doesn't implement scrollTo
Element.prototype.scrollTo = jest.fn();
Object.defineProperty(Element.prototype, 'scrollHeight', { configurable: true, value: 1000 });
Object.defineProperty(Element.prototype, 'scrollTop', { configurable: true, value: 0, writable: true });
Object.defineProperty(Element.prototype, 'clientHeight', { configurable: true, value: 500 });

// Mock clipboard API
Object.assign(navigator, { clipboard: { writeText: jest.fn().mockResolvedValue(undefined) } });

const mockMessages: Message[] = [
  {
    id: 'msg-1',
    conversation_id: 'conv-1',
    sender: 'agent',
    content: 'Hello from agent',
    timestamp: '2026-05-03T10:00:00Z',
    type: 'text',
  },
  {
    id: 'msg-2',
    conversation_id: 'conv-1',
    sender: 'user',
    content: 'Hello from user',
    timestamp: '2026-05-03T10:01:00Z',
    type: 'text',
  },
  {
    id: 'msg-3',
    conversation_id: 'conv-1',
    sender: 'agent',
    content: 'How can I help?',
    timestamp: '2026-05-03T10:02:00Z',
    type: 'text',
  },
];

describe('ChatView', () => {
  const mockOnSend = jest.fn();
  const mockOnMessagesChange = jest.fn();
  const mockLoadOlder = jest.fn().mockResolvedValue(undefined);

  const defaultProps = {
    messages: mockMessages,
    onSend: mockOnSend,
    connected: true,
    agentName: 'TestAgent',
    isTyping: false,
    token: 'test-token',
    userId: 'user-1',
    conversationId: 'conv-1',
    onMessagesChange: mockOnMessagesChange,
    loadOlderMessages: mockLoadOlder,
    hasOlderMessages: false,
    loadingOlder: false,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    // Set up mock implementations for API calls used in useEffect
    (api.getNotificationPrefs as jest.Mock).mockResolvedValue([]);
    (api.markConversationRead as jest.Mock).mockResolvedValue({ status: 'ok', count: 0 });
    (api.setNotificationPref as jest.Mock).mockResolvedValue({ conversation_id: 'conv-1', muted: true });
    (api.toggleReaction as jest.Mock).mockResolvedValue({ status: 'ok' });
    (api.editMessage as jest.Mock).mockResolvedValue({ status: 'ok', message_id: 'm1', content: 'edited', edited_at: '' });
    (api.deleteMessage as jest.Mock).mockResolvedValue({ status: 'ok', message_id: 'm1' });
  });

  it('renders messages correctly', () => {
    render(<ChatView {...defaultProps} />);
    expect(screen.getByText('Hello from agent')).toBeInTheDocument();
    expect(screen.getByText('Hello from user')).toBeInTheDocument();
    expect(screen.getByText('How can I help?')).toBeInTheDocument();
  });

  it('shows agent name in header', () => {
    render(<ChatView {...defaultProps} />);
    expect(screen.getByText('TestAgent')).toBeInTheDocument();
  });

  it('shows connected status when connected', () => {
    render(<ChatView {...defaultProps} />);
    expect(screen.getByText('● Connected')).toBeInTheDocument();
  });

  it('shows disconnected status when disconnected', () => {
    render(<ChatView {...defaultProps} connected={false} />);
    expect(screen.getByText('○ Disconnected')).toBeInTheDocument();
  });

  it('disables send button when disconnected', () => {
    render(<ChatView {...defaultProps} connected={false} />);
    expect(screen.getByRole('button', { name: 'Send message' })).toBeDisabled();
  });

  it('disables message input when disconnected', () => {
    render(<ChatView {...defaultProps} connected={false} />);
    expect(screen.getByLabelText('Message input')).toBeDisabled();
  });

  it('disables send button when input is empty', () => {
    render(<ChatView {...defaultProps} />);
    expect(screen.getByRole('button', { name: 'Send message' })).toBeDisabled();
  });

  it('sends message on form submit', async () => {
    render(<ChatView {...defaultProps} />);
    const input = screen.getByLabelText('Message input');
    await userEvent.type(input, 'Test message');
    fireEvent.submit(input.closest('form')!);
    expect(mockOnSend).toHaveBeenCalledWith('Test message', undefined);
  });

  it('sends message on Enter key', async () => {
    render(<ChatView {...defaultProps} />);
    const input = screen.getByLabelText('Message input');
    await userEvent.type(input, 'Hello world');
    fireEvent.keyDown(input, { key: 'Enter', shiftKey: false, ctrlKey: false, metaKey: false });
    expect(mockOnSend).toHaveBeenCalledWith('Hello world', undefined);
  });

  it('does not send on Shift+Enter', async () => {
    render(<ChatView {...defaultProps} />);
    const input = screen.getByLabelText('Message input');
    await userEvent.type(input, 'Hello');
    fireEvent.keyDown(input, { key: 'Enter', shiftKey: true });
    expect(mockOnSend).not.toHaveBeenCalled();
  });

  it('shows typing indicator when isTyping is true', () => {
    render(<ChatView {...defaultProps} isTyping={true} />);
    expect(screen.getByLabelText('Agent is typing')).toBeInTheDocument();
  });

  it('hides typing indicator when isTyping is false', () => {
    render(<ChatView {...defaultProps} isTyping={false} />);
    expect(screen.queryByLabelText('Agent is typing')).not.toBeInTheDocument();
  });

  it('shows date separator for Today', () => {
    render(<ChatView {...defaultProps} />);
    expect(screen.getByText('Today')).toBeInTheDocument();
  });

  it('shows read receipt (double check) for read user messages', () => {
    const messagesWithRead: Message[] = [
      { ...mockMessages[1], read_at: '2026-05-03T10:03:00Z' },
    ];
    render(<ChatView {...defaultProps} messages={messagesWithRead} />);
    expect(screen.getByText('✓✓')).toBeInTheDocument();
  });

  it('shows single check for unread user messages', () => {
    render(<ChatView {...defaultProps} />);
    expect(screen.getByText('✓')).toBeInTheDocument();
  });

  it('shows edited label for edited messages', () => {
    const editedMessages: Message[] = [
      { ...mockMessages[1], edited_at: '2026-05-03T10:05:00Z' },
    ];
    render(<ChatView {...defaultProps} messages={editedMessages} />);
    expect(screen.getByText('edited')).toBeInTheDocument();
  });

  it('shows deleted message styling', () => {
    const deletedMessages: Message[] = [
      { ...mockMessages[0], is_deleted: true },
    ];
    render(<ChatView {...defaultProps} messages={deletedMessages} />);
    expect(screen.getByText('Hello from agent')).toBeInTheDocument();
  });

  it('renders reaction chips with count', () => {
    const messagesWithReactions: Message[] = [
      { ...mockMessages[0], reactions: [
        { id: 'r1', message_id: 'msg-1', user_id: 'user-1', emoji: '👍', created_at: '2026-05-03T10:03:00Z' },
        { id: 'r2', message_id: 'msg-1', user_id: 'user-2', emoji: '👍', created_at: '2026-05-03T10:04:00Z' },
        { id: 'r3', message_id: 'msg-1', user_id: 'user-1', emoji: '❤️', created_at: '2026-05-03T10:05:00Z' },
      ]},
    ];
    render(<ChatView {...defaultProps} messages={messagesWithReactions} />);
    expect(screen.getByText(/👍/)).toBeInTheDocument();
    expect(screen.getByText(/❤️/)).toBeInTheDocument();
  });

  it('calls onSend with attachment IDs when attachments are pending', async () => {
    render(<ChatView {...defaultProps} />);
    await userEvent.click(screen.getByTestId('attachment-upload'));
    expect(screen.getByText('test.png')).toBeInTheDocument();
    const input = screen.getByLabelText('Message input');
    await userEvent.type(input, 'With attachment');
    fireEvent.submit(input.closest('form')!);
    await waitFor(() => {
      expect(mockOnSend).toHaveBeenCalledWith('With attachment', ['att-1']);
    });
  });

  it('shows placeholder text based on connection status', () => {
    render(<ChatView {...defaultProps} connected={true} />);
    expect(screen.getByPlaceholderText('Type a message... (Shift+Enter for newline)')).toBeInTheDocument();
  });

  it('shows "Connecting..." placeholder when disconnected', () => {
    render(<ChatView {...defaultProps} connected={false} />);
    expect(screen.getByPlaceholderText('Connecting...')).toBeInTheDocument();
  });

  it('has proper ARIA roles', () => {
    render(<ChatView {...defaultProps} />);
    expect(screen.getByRole('main', { name: /Chat with TestAgent/i })).toBeInTheDocument();
    expect(screen.getByRole('log', { name: 'Message history' })).toBeInTheDocument();
  });

  it('calls markConversationRead when messages change', async () => {
    render(<ChatView {...defaultProps} />);
    await waitFor(() => {
      expect(api.markConversationRead).toHaveBeenCalledWith('test-token', 'conv-1');
    });
  });

  it('renders back button when onBack is provided', () => {
    render(<ChatView {...defaultProps} onBack={() => {}} />);
    expect(screen.getByLabelText('Back to sidebar')).toBeInTheDocument();
  });

  it('does not render visible back button when onBack is not provided', () => {
    render(<ChatView {...defaultProps} />);
    const backBtn = screen.queryByLabelText('Back to sidebar');
    // The back button exists in DOM but is hidden with display:none when no onBack
    expect(backBtn).not.toBeVisible();
  });

  it('shows "Load older messages" button when hasOlderMessages is true', () => {
    render(<ChatView {...defaultProps} hasOlderMessages={true} />);
    expect(screen.getByText('↑ Load older messages')).toBeInTheDocument();
  });

  it('does not show load older button when hasOlderMessages is false', () => {
    render(<ChatView {...defaultProps} hasOlderMessages={false} />);
    expect(screen.queryByText('Load older messages')).not.toBeInTheDocument();
  });

  it('shows loading indicator when loadingOlder is true', () => {
    render(<ChatView {...defaultProps} loadingOlder={true} />);
    expect(screen.getByText('Loading older messages...')).toBeInTheDocument();
  });

  it('shows context menu with React option on right-click', async () => {
    render(<ChatView {...defaultProps} />);
    const agentMessageBubble = screen.getByText('Hello from agent').closest('.am-message-bubble')!;
    fireEvent.contextMenu(agentMessageBubble);
    await waitFor(() => {
      expect(screen.getByText('😊 React')).toBeInTheDocument();
    });
  });

  it('shows Edit and Delete options for user messages', async () => {
    render(<ChatView {...defaultProps} />);
    const userMessageBubble = screen.getByText('Hello from user').closest('.am-message-bubble')!;
    fireEvent.contextMenu(userMessageBubble);
    await waitFor(() => {
      expect(screen.getByText('✏️ Edit')).toBeInTheDocument();
      expect(screen.getByText('🗑️ Delete')).toBeInTheDocument();
    });
  });

  it('does not show Edit/Delete for agent messages', async () => {
    render(<ChatView {...defaultProps} />);
    const agentMessageBubble = screen.getByText('Hello from agent').closest('.am-message-bubble')!;
    fireEvent.contextMenu(agentMessageBubble);
    await waitFor(() => {
      expect(screen.queryByText('✏️ Edit')).not.toBeInTheDocument();
      expect(screen.queryByText('🗑️ Delete')).not.toBeInTheDocument();
    });
  });

  it('closes context menu on Escape', async () => {
    render(<ChatView {...defaultProps} />);
    const agentMessageBubble = screen.getByText('Hello from agent').closest('.am-message-bubble')!;
    fireEvent.contextMenu(agentMessageBubble);
    await waitFor(() => {
      expect(screen.getByText('😊 React')).toBeInTheDocument();
    });
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByText('😊 React')).not.toBeInTheDocument();
  });

  it('shows Copy option in context menu', async () => {
    render(<ChatView {...defaultProps} />);
    const messageBubble = screen.getByText('Hello from agent').closest('.am-message-bubble')!;
    fireEvent.contextMenu(messageBubble);
    await waitFor(() => {
      expect(screen.getByText('📋 Copy')).toBeInTheDocument();
    });
  });

  it('shows notification mute/unmute button', () => {
    render(<ChatView {...defaultProps} />);
    expect(screen.getByTitle('Notifications on (click to mute)')).toBeInTheDocument();
  });

  it('calls setNotificationPref when toggling mute', async () => {
    render(<ChatView {...defaultProps} />);
    const muteBtn = screen.getByTitle('Notifications on (click to mute)');
    await userEvent.click(muteBtn);
    await waitFor(() => {
      expect(api.setNotificationPref).toHaveBeenCalledWith('test-token', 'conv-1', true);
    });
  });
});