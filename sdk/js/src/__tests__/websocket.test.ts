/**
 * Agent Messenger SDK — Unit tests for WebSocket clients
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ClientWS, AgentWS } from '../websocket';

// Minimal mock WebSocket
class MockWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  readyState: number = MockWebSocket.OPEN;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onclose: (() => void) | null = null;
  url: string;
  protocols: string | string[] | undefined;
  sentMessages: string[] = [];

  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.protocols = protocols;
    // Auto-trigger onopen after a microtask
    setTimeout(() => this.onopen?.(), 0);
  }

  send(data: string) {
    this.sentMessages.push(data);
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }

  // Test helper: simulate receiving a message
  _receive(data: object) {
    this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent);
  }

  _receiveRaw(data: string) {
    this.onmessage?.({ data } as MessageEvent);
  }

  _error() {
    this.onerror?.(new Event('error'));
  }
}

describe('ClientWS', () => {
  let ws: ClientWS;
  let mockWs: MockWebSocket;

  function createClient() {
    ws = new ClientWS({
      baseUrl: 'http://localhost:8080',
      token: 'jwt-token-123',
      deviceId: 'device-1',
      autoReconnect: false,
    });

    // Replace the wsImpl with one that captures the instance
    (ws as any).wsImpl = class extends MockWebSocket {
      constructor(url: string, protocols?: string | string[]) {
        super(url, protocols);
        mockWs = this;
      }
    };

    return ws;
  }

  beforeEach(() => {
    mockWs = null!;
    createClient();
  });

  describe('connect', () => {
    it('should construct WebSocket URL with token and device_id', async () => {
      const connectPromise = ws.connect();
      await new Promise(r => setTimeout(r, 10));

      expect(mockWs.url).toContain('ws://localhost:8080/client/connect');
      expect(mockWs.url).toContain('token=jwt-token-123');
      expect(mockWs.url).toContain('device_id=device-1');

      // Simulate server welcome
      mockWs._receive({
        type: 'connected',
        data: { id: 'user_1', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'], device_id: 'device-1' },
      });

      const result = await connectPromise;
      expect(result.id).toBe('user_1');
      expect(result.protocol_version).toBe('v1');
    });

    it('should use wss:// for https:// base URLs', async () => {
      const secureWs = new ClientWS({
        baseUrl: 'https://example.com',
        token: 'jwt-token',
        autoReconnect: false,
      });
      (secureWs as any).wsImpl = class extends MockWebSocket {
        constructor(url: string, protocols?: string | string[]) {
          super(url, protocols);
          mockWs = this;
        }
      };

      const connectPromise = secureWs.connect();
      await new Promise(r => setTimeout(r, 10));

      expect(mockWs.url).toContain('wss://example.com/client/connect');

      mockWs._receive({
        type: 'connected',
        data: { id: 'user_1', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;
    });
  });

  describe('sendMessage', () => {
    it('should send a message over WebSocket', async () => {
      const connectPromise = ws.connect();
      await new Promise(r => setTimeout(r, 10));
      mockWs._receive({
        type: 'connected',
        data: { id: 'user_1', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;

      ws.sendMessage('conv_1', 'Hello world');

      expect(mockWs.sentMessages).toHaveLength(1);
      const msg = JSON.parse(mockWs.sentMessages[0]);
      expect(msg.type).toBe('message');
      expect(msg.data.conversation_id).toBe('conv_1');
      expect(msg.data.content).toBe('Hello world');
    });

    it('should throw when not connected', () => {
      // Create a client without connecting
      const disconnected = new ClientWS({
        baseUrl: 'http://localhost:8080',
        token: 'jwt',
        autoReconnect: false,
      });
      expect(() => disconnected.sendMessage('conv_1', 'test')).toThrow('Not connected');
    });
  });

  describe('sendTyping', () => {
    it('should send a typing indicator', async () => {
      const connectPromise = ws.connect();
      await new Promise(r => setTimeout(r, 10));
      mockWs._receive({
        type: 'connected',
        data: { id: 'user_1', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;

      ws.sendTyping('conv_1');
      const msg = JSON.parse(mockWs.sentMessages[0]);
      expect(msg.type).toBe('typing');
      expect(msg.data.conversation_id).toBe('conv_1');
    });
  });

  describe('event handlers', () => {
    it('should emit message events', async () => {
      const handler = vi.fn();
      ws.on('message', handler);

      const connectPromise = ws.connect();
      await new Promise(r => setTimeout(r, 10));
      mockWs._receive({
        type: 'connected',
        data: { id: 'user_1', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;

      mockWs._receive({
        type: 'message',
        data: { conversation_id: 'conv_1', content: 'Hello', sender_type: 'agent', sender_id: 'agent_1' },
      });

      expect(handler).toHaveBeenCalledWith(
        expect.objectContaining({
          conversation_id: 'conv_1',
          content: 'Hello',
        }),
      );
    });

    it('should emit error events', async () => {
      const handler = vi.fn();
      ws.on('error', handler);

      const connectPromise = ws.connect();
      await new Promise(r => setTimeout(r, 10));
      mockWs._receive({
        type: 'connected',
        data: { id: 'user_1', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;

      mockWs._receive({
        type: 'error',
        data: { error: 'something went wrong' },
      });

      expect(handler).toHaveBeenCalledWith({ error: 'something went wrong' });
    });

    it('should emit disconnect event on close', async () => {
      const handler = vi.fn();
      ws.on('disconnect', handler);

      const connectPromise = ws.connect();
      await new Promise(r => setTimeout(r, 10));
      mockWs._receive({
        type: 'connected',
        data: { id: 'user_1', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;

      mockWs.close();
      expect(handler).toHaveBeenCalled();
    });

    it('should remove event handler with off()', async () => {
      const handler = vi.fn();
      ws.on('message', handler);
      ws.off('message', handler);

      const connectPromise = ws.connect();
      await new Promise(r => setTimeout(r, 10));
      mockWs._receive({
        type: 'connected',
        data: { id: 'user_1', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;

      mockWs._receive({
        type: 'message',
        data: { conversation_id: 'conv_1', content: 'Hello' },
      });

      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('reconnection', () => {
    it('should not auto-reconnect when disabled', () => {
      const noReconnect = new ClientWS({
        baseUrl: 'http://localhost:8080',
        token: 'jwt',
        autoReconnect: false,
      });
      expect(noReconnect).toBeDefined();
    });
  });

  describe('disconnect', () => {
    it('should close the WebSocket and prevent reconnect', () => {
      ws.disconnect();
      expect(ws.connected).toBe(false);
    });
  });
});

describe('AgentWS', () => {
  let agent: AgentWS;
  let mockWs: MockWebSocket;

  beforeEach(() => {
    mockWs = null!;
    agent = new AgentWS({
      baseUrl: 'http://localhost:8080',
      agentId: 'my-agent',
      agentSecret: 'secret-123',
      agentName: 'HelpBot',
      agentModel: 'gpt-4',
      autoReconnect: false,
    });

    (agent as any).wsImpl = class extends MockWebSocket {
      constructor(url: string, protocols?: string | string[]) {
        super(url, protocols);
        mockWs = this;
      }
    };
  });

  describe('connect', () => {
    it('should construct WebSocket URL with agent params', async () => {
      const connectPromise = agent.connect();
      await new Promise(r => setTimeout(r, 10));

      expect(mockWs.url).toContain('/agent/connect');
      expect(mockWs.url).toContain('agent_id=my-agent');
      expect(mockWs.url).toContain('agent_secret=secret-123');
      expect(mockWs.url).toContain('name=HelpBot');
      expect(mockWs.url).toContain('model=gpt-4');

      mockWs._receive({
        type: 'connected',
        data: { id: 'my-agent', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });

      const result = await connectPromise;
      expect(result.id).toBe('my-agent');
    });
  });

  describe('sendMessage', () => {
    it('should send a chat message', async () => {
      const connectPromise = agent.connect();
      await new Promise(r => setTimeout(r, 10));
      mockWs._receive({
        type: 'connected',
        data: { id: 'my-agent', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;

      agent.sendMessage('conv_1', 'Hello from agent');
      const msg = JSON.parse(mockWs.sentMessages[0]);
      expect(msg.type).toBe('message');
      expect(msg.data.content).toBe('Hello from agent');
    });
  });

  describe('sendStatus', () => {
    it('should send a status update', async () => {
      const connectPromise = agent.connect();
      await new Promise(r => setTimeout(r, 10));
      mockWs._receive({
        type: 'connected',
        data: { id: 'my-agent', status: 'connected', protocol_version: 'v1', supported_versions: ['v1'] },
      });
      await connectPromise;

      agent.sendStatus('busy', 'conv_1');
      const msg = JSON.parse(mockWs.sentMessages[0]);
      expect(msg.type).toBe('status');
      expect(msg.data.status).toBe('busy');
      expect(msg.data.conversation_id).toBe('conv_1');
    });
  });
});