/**
 * Agent Messenger SDK — Integration tests for AgentMessengerClient and AgentClient
 */
import { describe, it, expect, vi } from 'vitest';
import { AgentMessengerClient, AgentClient } from '../index';
import { RestClient } from '../rest';

// Helper for mock fetch
function mockFetch(responses: Array<{ status: number; body: string }>) {
  let idx = 0;
  const fn = vi.fn(async () => {
    const resp = responses[idx] || responses[responses.length - 1];
    idx++;
    return {
      ok: resp.status >= 200 && resp.status < 300,
      status: resp.status,
      json: async () => JSON.parse(resp.body),
      text: async () => resp.body,
    } as Response;
  });
  return { fetch: fn };
}

describe('AgentMessengerClient', () => {
  it('should expose REST and WS clients', () => {
    const client = new AgentMessengerClient({
      baseUrl: 'http://localhost:8080',
      token: 'jwt-token',
    });
    expect(client.rest).toBeInstanceOf(RestClient);
    expect(client.ws).toBeDefined();
  });

  it('should update token on both clients after login', async () => {
    const client = new AgentMessengerClient({
      baseUrl: 'http://localhost:8080',
    });
    const { fetch: mockFn } = mockFetch([{
      status: 200,
      body: JSON.stringify({ token: 'new-jwt', user_id: 'user_1', username: 'alice' }),
    }]);
    (client.rest as any).fetchImpl = mockFn;

    const result = await client.login({ username: 'alice', password: 'secret' });
    expect(result.token).toBe('new-jwt');
    expect((client.rest as any).token).toBe('new-jwt');
    expect((client.ws as any).config.token).toBe('new-jwt');
  });

  it('should forward connect/disconnect to WS', () => {
    const client = new AgentMessengerClient({ baseUrl: 'http://localhost:8080', token: 'jwt' });
    // disconnect should not throw even if not connected
    client.disconnect();
    expect(client.ws.connected).toBe(false);
  });
});

describe('AgentClient', () => {
  it('should create an agent with WebSocket client', () => {
    const agent = new AgentClient({
      baseUrl: 'http://localhost:8080',
      agentId: 'test-agent',
      agentSecret: 'secret',
    });
    expect(agent.ws).toBeDefined();
  });

  it('should register and remove event handlers', () => {
    const agent = new AgentClient({
      baseUrl: 'http://localhost:8080',
      agentId: 'test-agent',
      agentSecret: 'secret',
    });
    const handler = vi.fn();
    agent.on('message', handler);
    expect((agent.ws as any).handlers.get('message')?.size).toBe(1);
    agent.off('message', handler);
    expect((agent.ws as any).handlers.get('message')?.size).toBe(0);
  });

  it('should disconnect cleanly', () => {
    const agent = new AgentClient({
      baseUrl: 'http://localhost:8080',
      agentId: 'test-agent',
      agentSecret: 'secret',
    });
    agent.disconnect();
    expect(agent.ws.connected).toBe(false);
  });
});