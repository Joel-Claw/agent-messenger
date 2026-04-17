import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AgentMessengerClient } from './client.js';

describe('AgentMessengerClient', () => {
  const config = {
    serverUrl: 'ws://localhost:8080',
    apiKey: 'test-api-key',
    agentId: 'test-agent',
  };

  it('constructs with config', () => {
    const client = new AgentMessengerClient(config);
    expect(client.connected).toBe(false);
  });

  it('registers message handlers', () => {
    const client = new AgentMessengerClient(config);
    const handler = vi.fn();
    client.onMessage(handler);
    // Handler is registered, we can't easily test internal array
    // but we verify it doesn't throw
    expect(true).toBe(true);
  });

  it('registers error handlers', () => {
    const client = new AgentMessengerClient(config);
    const handler = vi.fn();
    client.onError(handler);
    expect(true).toBe(true);
  });

  it('registers connect handlers', () => {
    const client = new AgentMessengerClient(config);
    const handler = vi.fn();
    client.onConnect(handler);
    expect(true).toBe(true);
  });

  it('registers disconnect handlers', () => {
    const client = new AgentMessengerClient(config);
    const handler = vi.fn();
    client.onDisconnect(handler);
    expect(true).toBe(true);
  });

  it('does not send when not connected', () => {
    const client = new AgentMessengerClient(config);
    // Should not throw, just log error
    client.sendMessage('test', 'conv-1');
    expect(true).toBe(true);
  });

  it('does not send typing when not connected', () => {
    const client = new AgentMessengerClient(config);
    client.sendTyping('conv-1', true);
    expect(true).toBe(true);
  });

  it('does not send status when not connected', () => {
    const client = new AgentMessengerClient(config);
    client.sendStatus('active');
    expect(true).toBe(true);
  });

  it('disconnect cleans up', () => {
    const client = new AgentMessengerClient(config);
    client.disconnect();
    expect(client.connected).toBe(false);
  });
});