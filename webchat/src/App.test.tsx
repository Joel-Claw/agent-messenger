import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

// Mock the WebSocket hook to avoid actual connections in tests
jest.mock('./hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    connected: false,
    send: jest.fn(),
    ws: null,
  }),
}));

// Mock the conversation history hook
jest.mock('./hooks/useConversationHistory', () => ({
  useConversationHistory: () => ({
    conversations: [],
    messages: [],
    activeConversationId: null,
    setActiveConversation: jest.fn(),
    loadHistory: jest.fn(),
    loadOlderMessages: jest.fn(),
    hasOlderMessages: false,
    loading: false,
    loadingOlder: false,
  }),
}));

describe('App', () => {
  it('renders without crashing', () => {
    render(<App />);
    // App should render the login screen since no token is provided
    expect(document.body).toBeTruthy();
  });

  it('shows login screen when not authenticated', () => {
    render(<App />);
    // Login form should be visible when no token is stored
    expect(screen.getByText('Agent Messenger')).toBeInTheDocument();
  });
});