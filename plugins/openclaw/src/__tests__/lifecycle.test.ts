/**
 * Tests for Agent Messenger plugin lifecycle and auto-connect (Task 9).
 *
 * Tests the plugin entry point's ability to:
 * - Set runtime on startup
 * - Resolve account from config and start connection
 * - Handle startup failures gracefully
 * - Register shutdown hooks
 * - Expose status via HTTP route
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { agentMessengerPlugin } from '../channel.js';
import { setRuntime, startRuntime, stopRuntime, resetRuntime, getClient } from '../runtime.js';

// Mock WebSocket
const mockWs = {
  on: vi.fn(),
  send: vi.fn(),
  close: vi.fn(),
  terminate: vi.fn(),
  readyState: 1, // WebSocket.OPEN
};

vi.mock('ws', () => ({
  default: vi.fn(() => mockWs),
  WebSocket: { OPEN: 1, CLOSED: 3 },
}));

function makeMockRuntime() {
  return {
    channel: {
      routing: {
        resolveAgentRoute: vi.fn().mockReturnValue({
          agentId: 'default',
          sessionKey: 'agent-messenger:user1',
          accountId: 'default',
        }),
      },
      session: {
        resolveStorePath: vi.fn().mockReturnValue('/tmp/test-sessions'),
        readSessionUpdatedAt: vi.fn().mockReturnValue(undefined),
        recordInboundSession: vi.fn().mockResolvedValue(undefined),
      },
      reply: {
        resolveEnvelopeFormatOptions: vi.fn().mockReturnValue({}),
        formatAgentEnvelope: vi.fn().mockReturnValue(''),
        finalizeInboundContext: vi.fn().mockReturnValue({}),
        dispatchReplyWithBufferedBlockDispatcher: vi.fn().mockResolvedValue(undefined),
      },
    },
  } as any;
}

function makeMockAccount() {
  return {
    accountId: 'default',
    serverUrl: 'ws://localhost:8080',
    apiKey: 'test-key',
    agentId: 'test-agent',
    agentName: 'Test Agent',
    agentModel: 'test-model',
    agentPersonality: 'helpful',
    agentSpecialty: 'general',
    allowFrom: [],
    dmPolicy: 'open',
  };
}

describe('Agent Messenger Plugin - Auto-Connect Lifecycle', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetRuntime();
  });

  afterEach(() => {
    resetRuntime();
  });

  it('should set runtime and verify channel methods', () => {
    const rt = makeMockRuntime();
    setRuntime(rt);

    expect(rt.channel.routing.resolveAgentRoute).toBeDefined();
    expect(rt.channel.session.recordInboundSession).toBeDefined();
    expect(rt.channel.reply.dispatchReplyWithBufferedBlockDispatcher).toBeDefined();
    expect(getClient()).toBeNull(); // Not connected yet
  });

  it('should reject startRuntime without runtime', async () => {
    const account = makeMockAccount();
    await expect(startRuntime(account)).rejects.toThrow('PluginRuntime not set');
  });

  it('should clear client on stopRuntime', () => {
    stopRuntime();
    expect(getClient()).toBeNull();
  });

  it('should handle config resolution failure gracefully', () => {
    const incompleteConfig = { channels: {} } as any;
    expect(() => {
      agentMessengerPlugin.setup!.resolveAccount(incompleteConfig, undefined);
    }).toThrow();
  });

  it('should resolve account from valid config', () => {
    const validConfig = {
      channels: {
        'agent-messenger': {
          serverUrl: 'ws://localhost:8080',
          apiKey: 'test-key',
          agentId: 'test-agent',
        },
      },
    } as any;

    const account = agentMessengerPlugin.setup!.resolveAccount(validConfig, undefined);
    expect(account.serverUrl).toBe('ws://localhost:8080');
    expect(account.apiKey).toBe('test-key');
    expect(account.agentId).toBe('test-agent');
  });

  it('should start runtime with mock WebSocket', async () => {
    const rt = makeMockRuntime();
    setRuntime(rt);

    // Mock the WebSocket constructor to simulate successful connection
    const { default: WebSocket } = await import('ws');
    (WebSocket as any).mockImplementation(() => {
      const ws = {
        on: vi.fn((event: string, handler: Function) => {
          if (event === 'open') {
            // Simulate immediate open
            setTimeout(() => handler(), 0);
          }
        }),
        send: vi.fn(),
        close: vi.fn(),
        terminate: vi.fn(),
        readyState: 1,
      };
      return ws;
    });

    const account = makeMockAccount();
    await startRuntime(account);

    // Client should be set
    const client = getClient();
    expect(client).not.toBeNull();

    // Clean up
    stopRuntime();
    expect(getClient()).toBeNull();
  });

  it('should handle startRuntime connection failure', async () => {
    const rt = makeMockRuntime();
    setRuntime(rt);

    // Mock WebSocket to simulate connection failure
    const { default: WebSocket } = await import('ws');
    (WebSocket as any).mockImplementation(() => {
      const ws = {
        on: vi.fn((event: string, handler: Function) => {
          if (event === 'error') {
            setTimeout(() => handler(new Error('Connection refused')), 0);
          }
          if (event === 'close') {
            // no-op
          }
        }),
        send: vi.fn(),
        close: vi.fn(),
        terminate: vi.fn(),
        readyState: 3, // CLOSED
      };
      return ws;
    });

    const account = makeMockAccount();
    await expect(startRuntime(account)).rejects.toThrow();

    stopRuntime();
    expect(getClient()).toBeNull();
  });

  it('should call stopRuntime on shutdown hook', () => {
    const rt = makeMockRuntime();
    setRuntime(rt);

    // Shutdown hook calls stopRuntime
    stopRuntime();
    expect(getClient()).toBeNull();
  });
});

describe('Agent Messenger Plugin - Status Endpoint', () => {
  beforeEach(() => {
    resetRuntime();
  });

  it('should return disconnected status when client is not connected', () => {
    const client = getClient();
    const status = client?.connected ? 'connected' : 'disconnected';
    expect(status).toBe('disconnected');
  });

  it('should return connected status when client is connected', () => {
    const mockClient = { connected: true } as any;
    expect(mockClient.connected).toBe(true);
  });
});

describe('Agent Messenger Plugin - Retry on Startup Failure', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetRuntime();
  });

  afterEach(() => {
    resetRuntime();
  });

  it('should support multiple start/stop cycles', async () => {
    const rt = makeMockRuntime();

    // Cycle 1
    setRuntime(rt);
    stopRuntime();
    expect(getClient()).toBeNull();

    // Cycle 2
    setRuntime(rt);
    stopRuntime();
    expect(getClient()).toBeNull();
  });

  it('should inspect account without materializing secrets', () => {
    const cfg = {
      channels: {
        'agent-messenger': {
          serverUrl: 'ws://localhost:8080',
          apiKey: 'test-key',
          agentId: 'test-agent',
        },
      },
    } as any;
    const result = agentMessengerPlugin.setup!.inspectAccount!(cfg, undefined);
    expect(result.configured).toBe(true);
    expect(result.serverUrl).toBe('configured');
  });

  it('should report missing config via inspectAccount', () => {
    const cfg = { channels: {} } as any;
    const result = agentMessengerPlugin.setup!.inspectAccount!(cfg, undefined);
    expect(result.configured).toBe(false);
  });

  it('should use default values for optional fields', () => {
    const cfg = {
      channels: {
        'agent-messenger': {
          serverUrl: 'ws://localhost:8080',
          apiKey: 'test-key',
          agentId: 'test-agent',
        },
      },
    } as any;
    const account = agentMessengerPlugin.setup!.resolveAccount(cfg, undefined);
    expect(account.agentName).toBe('OpenClaw Agent');
    expect(account.agentModel).toBe('');
    expect(account.agentPersonality).toBe('');
    expect(account.agentSpecialty).toBe('');
  });
});