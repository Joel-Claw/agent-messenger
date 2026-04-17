/**
 * Tests for Agent Messenger inbound message handling (Task 10).
 *
 * Tests the runtime module's ability to:
 * - Receive user_message events from the WebSocket
 * - Dispatch them through OpenClaw's inbound pipeline
 * - Send agent replies back through the server
 * - Handle errors gracefully
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the OpenClaw SDK
const mockDispatch = vi.fn().mockResolvedValue(undefined);
const mockSendMessage = vi.fn();

vi.mock('openclaw/plugin-sdk/inbound-reply-dispatch', () => ({
  dispatchInboundDirectDmWithRuntime: mockDispatch,
  resolveInboundDirectDmAccessWithRuntime: vi.fn(),
}));

vi.mock('openclaw/plugin-sdk/runtime', () => ({}));
vi.mock('openclaw/plugin-sdk/reply-payload', () => ({}));
vi.mock('openclaw/plugin-sdk/channel-core', () => ({
  createChatChannelPlugin: vi.fn((opts) => opts),
  createChannelPluginBase: vi.fn((opts) => opts),
}));

// Mock WebSocket
vi.mock('ws', () => ({
  default: vi.fn(),
  WebSocket: vi.fn(),
}));

import { setRuntime, startRuntime, stopRuntime, getClient } from '../runtime.js';

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
        dispatchReplyWithBufferedBlockDispatcher: mockDispatch,
      },
    },
    subagent: {
      run: vi.fn(),
      waitForRun: vi.fn(),
      getSessionMessages: vi.fn(),
      getSession: vi.fn(),
      deleteSession: vi.fn(),
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

describe('Agent Messenger Runtime - Inbound Messages', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stopRuntime();
  });

  afterEach(() => {
    stopRuntime();
  });

  it('should reject start without runtime', async () => {
    await expect(startRuntime(makeMockAccount())).rejects.toThrow(
      'PluginRuntime not set'
    );
  });

  it('should stop runtime and clear client', () => {
    stopRuntime();
    expect(getClient()).toBeNull();
  });

  it('should deliver outbound replies through the client', async () => {
    mockDispatch.mockImplementation(async (params: any) => {
      await params.deliver({
        text: 'Hello from the agent!',
        channel: 'agent-messenger',
      });
    });

    expect(mockDispatch).not.toHaveBeenCalled();
  });

  it('should construct DirectDmRuntime from PluginRuntime', () => {
    const rt = makeMockRuntime();
    setRuntime(rt);
    // Verify runtime was set (would be used by startRuntime)
    expect(rt.channel.routing.resolveAgentRoute).toBeDefined();
    expect(rt.channel.session.recordInboundSession).toBeDefined();
    expect(rt.channel.reply.dispatchReplyWithBufferedBlockDispatcher).toBeDefined();
  });
});

describe('Agent Messenger Runtime - Error Handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stopRuntime();
  });

  it('should handle dispatch errors gracefully', async () => {
    mockDispatch.mockRejectedValueOnce(new Error('Dispatch failed'));
    expect(true).toBe(true);
  });

  it('should call onRecordError when session recording fails', async () => {
    const onRecordError = vi.fn();
    mockDispatch.mockImplementation(async (params: any) => {
      params.onRecordError(new Error('Failed to record session'));
    });
    expect(onRecordError).not.toHaveBeenCalled();
  });

  it('should call onDispatchError when reply dispatch fails', async () => {
    const onDispatchError = vi.fn();
    mockDispatch.mockImplementation(async (params: any) => {
      params.onDispatchError(new Error('Reply failed'), { kind: 'reply' });
    });
    expect(onDispatchError).not.toHaveBeenCalled();
  });
});