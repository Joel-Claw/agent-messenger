import { describe, it, expect } from 'vitest';
import { agentMessengerPlugin } from './channel.js';

describe('agent-messenger plugin', () => {
  it('resolves account from config', () => {
    const cfg = {
      channels: {
        'agent-messenger': {
          serverUrl: 'ws://localhost:8080',
          apiKey: 'test-key',
          agentId: 'test-agent',
          agentName: 'Test Agent',
          allowFrom: ['user1'],
        },
      },
    } as any;
    const account = agentMessengerPlugin.setup!.resolveAccount(cfg, undefined);
    expect(account.serverUrl).toBe('ws://localhost:8080');
    expect(account.apiKey).toBe('test-key');
    expect(account.agentId).toBe('test-agent');
    expect(account.agentName).toBe('Test Agent');
    expect(account.allowFrom).toEqual(['user1']);
  });

  it('inspects account without materializing secrets', () => {
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

  it('reports missing config', () => {
    const cfg = { channels: {} } as any;
    const result = agentMessengerPlugin.setup!.inspectAccount!(cfg, undefined);
    expect(result.configured).toBe(false);
  });

  it('reports partial config as not configured', () => {
    const cfg = {
      channels: {
        'agent-messenger': {
          serverUrl: 'ws://localhost:8080',
          // Missing apiKey and agentId
        },
      },
    } as any;
    const result = agentMessengerPlugin.setup!.inspectAccount!(cfg, undefined);
    expect(result.configured).toBe(false);
  });

  it('throws on resolveAccount with missing required fields', () => {
    const cfg = { channels: {} } as any;
    expect(() => agentMessengerPlugin.setup!.resolveAccount(cfg, undefined)).toThrow();
  });

  it('uses default values for optional fields', () => {
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

  it('has DM security config', () => {
    const cfg = {
      channels: {
        'agent-messenger': {
          serverUrl: 'ws://localhost:8080',
          apiKey: 'test-key',
          agentId: 'test-agent',
          dmSecurity: 'open',
          allowFrom: [],
        },
      },
    } as any;
    const account = agentMessengerPlugin.setup!.resolveAccount(cfg, undefined);
    expect(account.dmPolicy).toBe('open');
  });

  it('defaults to allowlist DM policy', () => {
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
    expect(account.dmPolicy).toBeUndefined();
  });

  it('has outbound sendText method', () => {
    expect(agentMessengerPlugin.outbound?.attachedResults?.sendText).toBeDefined();
  });

  it('has outbound sendMedia method', () => {
    expect(agentMessengerPlugin.outbound?.base?.sendMedia).toBeDefined();
  });
});