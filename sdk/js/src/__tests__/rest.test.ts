/**
 * Agent Messenger SDK — Unit tests for REST client
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RestClient, ApiError } from '../rest';

// Mock fetch
function mockFetch(responses: Array<{ status: number; body: string; headers?: Record<string, string> }>) {
  const calls: Array<{ url: string; method: string; headers: Record<string, string>; body?: string }> = [];
  let idx = 0;

  const fn = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({
      url,
      method: init?.method || 'GET',
      headers: (init?.headers as Record<string, string>) || {},
      body: typeof init?.body === 'string' ? init.body : undefined,
    });
    const resp = responses[idx] || responses[responses.length - 1];
    idx++;
    return {
      ok: resp.status >= 200 && resp.status < 300,
      status: resp.status,
      headers: new Headers(resp.headers || {}),
      json: async () => JSON.parse(resp.body),
      text: async () => resp.body,
    } as Response;
  });

  return { fetch: fn, calls };
}

describe('RestClient', () => {
  let client: RestClient;

  beforeEach(() => {
    client = new RestClient('http://localhost:8080', 'test-jwt-token');
  });

  describe('constructor', () => {
    it('should strip trailing slashes from baseUrl', () => {
      const c = new RestClient('http://localhost:8080///');
      expect((c as any).baseUrl).toBe('http://localhost:8080');
    });

    it('should accept a token', () => {
      const c = new RestClient('http://localhost:8080', 'my-token');
      expect((c as any).token).toBe('my-token');
    });
  });

  describe('setToken', () => {
    it('should update the stored token', () => {
      client.setToken('new-token');
      expect((client as any).token).toBe('new-token');
    });
  });

  describe('login', () => {
    it('should POST to /auth/login and store the returned token', async () => {
      const { fetch: mockFn, calls } = mockFetch([{
        status: 200,
        body: JSON.stringify({ token: 'jwt-abc', user_id: 'user_1', username: 'alice' }),
      }]);
      (client as any).fetchImpl = mockFn;

      const result = await client.login({ username: 'alice', password: 'secret' });

      expect(result.token).toBe('jwt-abc');
      expect(result.user_id).toBe('user_1');
      expect(result.username).toBe('alice');
      expect(calls[0].method).toBe('POST');
      expect(calls[0].url).toContain('/auth/login');
      expect(calls[0].body).toContain('username=alice');
      // Token should be stored
      expect((client as any).token).toBe('jwt-abc');
    });
  });

  describe('registerUser', () => {
    it('should POST to /auth/user', async () => {
      const { fetch: mockFn } = mockFetch([{
        status: 200,
        body: JSON.stringify({ user_id: 'user_2', username: 'bob', status: 'registered' }),
      }]);
      (client as any).fetchImpl = mockFn;

      const result = await client.registerUser({ username: 'bob', password: 'pass123' });
      expect(result.user_id).toBe('user_2');
      expect(result.username).toBe('bob');
    });
  });

  describe('listAgents', () => {
    it('should GET /agents with auth header', async () => {
      const { fetch: mockFn, calls } = mockFetch([{
        status: 200,
        body: JSON.stringify([
          { agent_id: 'agent_1', name: 'Bot', model: 'gpt-4', personality: 'friendly', specialty: 'help', status: 'online' },
        ]),
      }]);
      (client as any).fetchImpl = mockFn;

      const agents = await client.listAgents();
      expect(agents).toHaveLength(1);
      expect(agents[0].agent_id).toBe('agent_1');
      expect(calls[0].headers['Authorization']).toBe('Bearer test-jwt-token');
    });
  });

  describe('createConversation', () => {
    it('should POST to /conversations/create', async () => {
      const { fetch: mockFn } = mockFetch([{
        status: 200,
        body: JSON.stringify({ conversation_id: 'conv_1', user_id: 'user_1', agent_id: 'agent_1' }),
      }]);
      (client as any).fetchImpl = mockFn;

      const conv = await client.createConversation({ agent_id: 'agent_1' });
      expect(conv.conversation_id).toBe('conv_1');
    });
  });

  describe('getMessages', () => {
    it('should GET /conversations/messages with query params', async () => {
      const { fetch: mockFn, calls } = mockFetch([{
        status: 200,
        body: JSON.stringify([{ message_id: 'msg_1', content: 'hello' }]),
      }]);
      (client as any).fetchImpl = mockFn;

      const msgs = await client.getMessages('conv_1', 20);
      expect(msgs).toHaveLength(1);
      expect(calls[0].url).toContain('conversation_id=conv_1');
      expect(calls[0].url).toContain('limit=20');
    });
  });

  describe('searchMessages', () => {
    it('should GET /messages/search with query', async () => {
      const { fetch: mockFn, calls } = mockFetch([{
        status: 200,
        body: JSON.stringify([{ message_id: 'msg_1', content: 'hello world' }]),
      }]);
      (client as any).fetchImpl = mockFn;

      const results = await client.searchMessages('hello', 10);
      expect(results).toHaveLength(1);
      expect(calls[0].url).toContain('q=hello');
      expect(calls[0].url).toContain('limit=10');
    });
  });

  describe('editMessage', () => {
    it('should POST to /messages/edit', async () => {
      const { fetch: mockFn } = mockFetch([{
        status: 200,
        body: JSON.stringify({ status: 'edited' }),
      }]);
      (client as any).fetchImpl = mockFn;

      const result = await client.editMessage({ message_id: 'msg_1', content: 'updated' });
      expect(result.status).toBe('edited');
    });
  });

  describe('deleteMessage', () => {
    it('should POST to /messages/delete', async () => {
      const { fetch: mockFn } = mockFetch([{
        status: 200,
        body: JSON.stringify({ status: 'deleted' }),
      }]);
      (client as any).fetchImpl = mockFn;

      const result = await client.deleteMessage('msg_1');
      expect(result.status).toBe('deleted');
    });
  });

  describe('react', () => {
    it('should POST to /messages/react', async () => {
      const { fetch: mockFn } = mockFetch([{
        status: 200,
        body: JSON.stringify({ action: 'added', emoji: '👍' }),
      }]);
      (client as any).fetchImpl = mockFn;

      const result = await client.react('msg_1', '👍');
      expect(result.action).toBe('added');
      expect(result.emoji).toBe('👍');
    });
  });

  describe('presence', () => {
    it('should GET /presence', async () => {
      const { fetch: mockFn } = mockFetch([{
        status: 200,
        body: JSON.stringify([{ agent_id: 'agent_1', status: 'online', last_seen: '2026-01-01T00:00:00Z' }]),
      }]);
      (client as any).fetchImpl = mockFn;

      const presence = await client.getPresence();
      expect(presence).toHaveLength(1);
      expect(presence[0].agent_id).toBe('agent_1');
    });
  });

  describe('tags', () => {
    it('should add, remove, and list tags', async () => {
      const { fetch: mockFn } = mockFetch([
        { status: 200, body: JSON.stringify({ status: 'added' }) },
        { status: 200, body: JSON.stringify({ status: 'removed' }) },
        { status: 200, body: JSON.stringify([{ tag: 'important', created_at: '2026-01-01T00:00:00Z' }]) },
      ]);
      (client as any).fetchImpl = mockFn;

      await client.addTag({ conversation_id: 'conv_1', tag: 'important' });
      await client.removeTag({ conversation_id: 'conv_1', tag: 'important' });
      const tags = await client.getTags('conv_1');
      expect(tags).toHaveLength(1);
      expect(tags[0].tag).toBe('important');
    });
  });

  describe('health', () => {
    it('should GET /health without auth', async () => {
      const healthClient = new RestClient('http://localhost:8080');
      const { fetch: mockFn } = mockFetch([{
        status: 200,
        body: JSON.stringify({ status: 'ok', uptime: '1h', version: '0.1.0' }),
      }]);
      (healthClient as any).fetchImpl = mockFn;

      const health = await healthClient.health();
      expect(health.status).toBe('ok');
    });
  });

  describe('error handling', () => {
    it('should throw ApiError on non-2xx responses', async () => {
      const { fetch: mockFn } = mockFetch([{
        status: 401,
        body: 'unauthorized',
      }]);
      (client as any).fetchImpl = mockFn;

      await expect(client.listAgents()).rejects.toThrow(ApiError);
      await expect(client.listAgents()).rejects.toThrow('401');
    });
  });

  describe('E2E encryption', () => {
    it('should upload and retrieve key bundles', async () => {
      const { fetch: mockFn } = mockFetch([
        { status: 200, body: JSON.stringify({ status: 'ok' }) },
        { status: 200, body: JSON.stringify({ identity_key: 'ik', signed_prekey: 'spk', prekey_signature: 'sig', one_time_prekey: 'otpk' }) },
      ]);
      (client as any).fetchImpl = mockFn;

      await client.uploadKeyBundle({
        identity_key: 'ik',
        signed_prekey: 'spk',
        prekey_signature: 'sig',
        one_time_prekeys: ['otpk1'],
      });

      const bundle = await client.getKeyBundle('user_1');
      expect(bundle.identity_key).toBe('ik');
    });

    it('should store and retrieve encrypted messages', async () => {
      const { fetch: mockFn } = mockFetch([
        { status: 200, body: JSON.stringify({ id: 'enc_1' }) },
        { status: 200, body: JSON.stringify([{ id: 'enc_1', ciphertext: 'abc' }]) },
      ]);
      (client as any).fetchImpl = mockFn;

      const result = await client.storeEncryptedMessage({
        conversation_id: 'conv_1',
        ciphertext: 'abc',
        sender_device_id: 'dev_1',
        message_type: 1,
      });
      expect(result.id).toBe('enc_1');

      const msgs = await client.getEncryptedMessages('conv_1');
      expect(msgs).toHaveLength(1);
    });
  });

  describe('push notifications', () => {
    it('should register and unregister device tokens', async () => {
      const { fetch: mockFn } = mockFetch([
        { status: 200, body: JSON.stringify({ status: 'registered' }) },
        { status: 200, body: JSON.stringify({ status: 'unregistered' }) },
      ]);
      (client as any).fetchImpl = mockFn;

      await client.registerDeviceToken({ device_token: 'device-token-123', platform: 'android' });
      await client.unregisterDeviceToken({ device_token: 'device-token-123' });
    });

    it('should get VAPID key', async () => {
      const { fetch: mockFn, calls } = mockFetch([
        { status: 200, body: JSON.stringify({ public_key: 'BPxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }) },
      ]);
      (client as any).fetchImpl = mockFn;

      const result = await client.getVAPIDKey();
      expect(result.public_key).toBe('BPxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
      expect(calls[0].method).toBe('GET');
      expect(calls[0].url).toContain('/push/vapid-key');
    });

    it('should subscribe to web push', async () => {
      const { fetch: mockFn, calls } = mockFetch([
        { status: 200, body: JSON.stringify({ status: 'subscribed' }) },
      ]);
      (client as any).fetchImpl = mockFn;

      const result = await client.webPushSubscribe({
        endpoint: 'https://push.example.com/sub/123',
        keys: { p256dh: 'key1', auth: 'auth1' },
      });
      expect(result.status).toBe('subscribed');
      expect(calls[0].method).toBe('POST');
      expect(calls[0].url).toContain('/push/web-subscribe');
    });

    it('should unsubscribe from web push', async () => {
      const { fetch: mockFn, calls } = mockFetch([
        { status: 200, body: JSON.stringify({ status: 'unsubscribed' }) },
      ]);
      (client as any).fetchImpl = mockFn;

      const result = await client.webPushUnsubscribe({ endpoint: 'https://push.example.com/sub/123' });
      expect(result.status).toBe('unsubscribed');
      expect(calls[0].method).toBe('POST');
      expect(calls[0].url).toContain('/push/web-unsubscribe');
    });
  });

  describe('rate limiting', () => {
    it('should get and set rate limit tiers', async () => {
      const { fetch: mockFn } = mockFetch([
        { status: 200, body: JSON.stringify({ user_id: 'user_1', tier: 'pro', burst: 300, window_sec: 60, remaining: 299 }) },
        { status: 200, body: JSON.stringify({ status: 'updated', user_id: 'user_1', tier: 'enterprise' }) },
      ]);
      (client as any).fetchImpl = mockFn;

      const tierInfo = await client.getRateLimitTier('user_1');
      expect(tierInfo.tier).toBe('pro');

      const result = await client.setRateLimitTier({ user_id: 'user_1', tier: 'enterprise' });
      expect(result.tier).toBe('enterprise');
    });
  });
});