import * as api from '../services/api';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('API Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('login', () => {
    it('calls /auth/login with form-encoded data', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ token: 'jwt-token', user_id: 'user-1', username: 'testuser' }),
      });

      const result = await api.login('testuser', 'testpass');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/auth/login'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
          }),
        })
      );
      expect(result.token).toBe('jwt-token');
      expect(result.user_id).toBe('user-1');
    });

    it('throws on failed login', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: 'Invalid credentials' }),
      });

      await expect(api.login('bad', 'bad')).rejects.toThrow('Invalid credentials');
    });

    it('throws default error on non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.reject(new Error('Not JSON')),
      });

      await expect(api.login('bad', 'bad')).rejects.toThrow('Login failed');
    });
  });

  describe('register', () => {
    it('calls /auth/register with form-encoded data', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ user_id: 'user-1', username: 'newuser' }),
      });

      const result = await api.register('newuser', 'newpass');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/auth/register'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
          }),
        })
      );
      expect(result.username).toBe('newuser');
    });

    it('throws on duplicate registration', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: 'Username already taken' }),
      });

      await expect(api.register('existing', 'pass')).rejects.toThrow('Username already taken');
    });
  });

  describe('getAgents', () => {
    it('fetches agents with auth token', async () => {
      const agents = [
        { id: 'a1', name: 'Agent 1', model: 'gpt-4', personality: 'friendly', specialty: 'coding', status: 'online' },
      ];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ agents }),
      });

      const result = await api.getAgents('my-token');
      expect(result).toEqual(agents);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/agents'),
        expect.objectContaining({
          headers: expect.objectContaining({ Authorization: 'Bearer my-token' }),
        })
      );
    });

    it('handles agents as direct array', async () => {
      const agents = [
        { id: 'a1', name: 'Agent 1', model: 'gpt-4', personality: 'friendly', specialty: 'coding', status: 'online' },
      ];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(agents),
      });

      const result = await api.getAgents('my-token');
      expect(result).toEqual(agents);
    });

    it('throws on failure', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false });
      await expect(api.getAgents('token')).rejects.toThrow('Failed to fetch agents');
    });
  });

  describe('getConversations', () => {
    it('fetches conversations with auth token', async () => {
      const convs = [{ id: 'conv-1', user_id: 'u1', agent_id: 'a1', created_at: '', updated_at: '' }];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(convs),
      });

      const result = await api.getConversations('my-token');
      expect(result).toEqual(convs);
    });
  });

  describe('getMessages', () => {
    it('fetches messages with pagination options', async () => {
      const msgs = [{ id: 'm1', content: 'hello' }];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(msgs),
      });

      const result = await api.getMessages('token', 'conv-1', { before: 'msg-5', limit: 20 });
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('conversation_id=conv-1'),
        expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer token' }) })
      );
      expect(mockFetch.mock.calls[0][0]).toContain('before=msg-5');
      expect(mockFetch.mock.calls[0][0]).toContain('limit=20');
    });

    it('works without pagination options', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([]),
      });

      const result = await api.getMessages('token', 'conv-1');
      expect(mockFetch.mock.calls[0][0]).toContain('conversation_id=conv-1');
      expect(mockFetch.mock.calls[0][0]).not.toContain('before');
      expect(mockFetch.mock.calls[0][0]).not.toContain('limit');
    });
  });

  describe('toggleReaction', () => {
    it('calls /messages/react with form data', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ status: 'added', reaction: { id: 'r1', message_id: 'm1', user_id: 'u1', emoji: '👍', created_at: '' } }),
      });

      const result = await api.toggleReaction('token', 'm1', '👍');
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/messages/react'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            Authorization: 'Bearer token',
            'X-Requested-With': 'XMLHttpRequest',
          }),
        })
      );
    });
  });

  describe('editMessage', () => {
    it('calls /messages/edit with form data', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ status: 'ok', message_id: 'm1', content: 'edited', edited_at: '2026-05-03T00:00:00Z' }),
      });

      const result = await api.editMessage('token', 'm1', 'edited content');
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/messages/edit'),
        expect.objectContaining({ method: 'POST' })
      );
      expect(result.content).toBe('edited');
    });
  });

  describe('deleteMessage', () => {
    it('calls /messages/delete with form data', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ status: 'ok', message_id: 'm1' }),
      });

      const result = await api.deleteMessage('token', 'm1');
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/messages/delete'),
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('markConversationRead', () => {
    it('calls /conversations/mark-read', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ status: 'ok', count: 5 }),
      });

      const result = await api.markConversationRead('token', 'conv-1');
      expect(result.count).toBe(5);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/conversations/mark-read'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({ Authorization: 'Bearer token' }),
        })
      );
    });
  });

  describe('getPresence', () => {
    it('fetches presence data', async () => {
      const presence = [
        { id: 'a1', name: 'Agent 1', online: true, status: 'online' },
      ];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(presence),
      });

      const result = await api.getPresence('token');
      expect(result).toEqual(presence);
    });
  });

  describe('notification preferences', () => {
    it('fetches notification prefs', async () => {
      const prefs = [{ conversation_id: 'conv-1', muted: false }];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(prefs),
      });

      const result = await api.getNotificationPrefs('token');
      expect(result).toEqual(prefs);
    });

    it('sets notification pref', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ conversation_id: 'conv-1', muted: true }),
      });

      const result = await api.setNotificationPref('token', 'conv-1', true);
      expect(result.muted).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/notification-prefs/set'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({ Authorization: 'Bearer token' }),
        })
      );
    });
  });

  describe('CSRF headers', () => {
    it('includes X-Requested-With on state-changing requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ token: 't', user_id: 'u', username: 'n' }),
      });

      await api.login('u', 'p');
      expect(mockFetch.mock.calls[0][1].headers).toMatchObject({
        'X-Requested-With': 'XMLHttpRequest',
      });
    });
  });

  describe('helper functions', () => {
    it('formats file sizes correctly', () => {
      expect(api.formatFileSize(0)).toBe('0 B');
      expect(api.formatFileSize(512)).toBe('512 B');
      expect(api.formatFileSize(1024)).toBe('1.0 KB');
      expect(api.formatFileSize(1048576)).toBe('1.0 MB');
      expect(api.formatFileSize(1073741824)).toBe('1.0 GB');
    });

    it('detects image content types', () => {
      expect(api.isImageContentType('image/png')).toBe(true);
      expect(api.isImageContentType('image/jpeg')).toBe(true);
      expect(api.isImageContentType('text/plain')).toBe(false);
    });

    it('detects audio content types', () => {
      expect(api.isAudioContentType('audio/mp3')).toBe(true);
      expect(api.isAudioContentType('video/mp4')).toBe(false);
    });

    it('detects video content types', () => {
      expect(api.isVideoContentType('video/mp4')).toBe(true);
      expect(api.isVideoContentType('image/png')).toBe(false);
    });

    it('generates attachment URL', () => {
      expect(api.getAttachmentUrl('att-123')).toContain('/attachments/att-123');
    });
  });
});