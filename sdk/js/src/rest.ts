/**
 * Agent Messenger SDK — REST API client
 */

import type {
  Agent,
  AdminAgent,
  Attachment,
  ChangePasswordRequest,
  Conversation,
  CreateConversationRequest,
  EditMessageRequest,
  EncryptedMessage,
  HealthResponse,
  KeyBundle,
  LoginRequest,
  LoginResponse,
  MarkReadResponse,
  Message,
  PresenceEntry,
  RateLimitInfo,
  ReactResponse,
  RegisterAgentRequest,
  RegisterAgentResponse,
  RegisterPushRequest,
  RegisterUserRequest,
  RegisterUserResponse,
  SearchMessagesResponse,
  SetRateLimitTierRequest,
  StoreEncryptedMessageRequest,
  Tag,
  TagRequest,
  UnregisterPushRequest,
  VAPIDKeyResponse,
  WebPushSubscribeRequest,
  WebPushSubscribeResponse,
  WebPushUnsubscribeRequest,
  WebPushUnsubscribeResponse,
  UploadAttachmentResponse,
  UploadKeyBundleRequest,
} from './types';

export class ApiError extends Error {
  constructor(
    public status: number,
    public body: string,
  ) {
    super(`API error ${status}: ${body}`);
    this.name = 'ApiError';
  }
}

export class RestClient {
  private baseUrl: string;
  private token: string | undefined;
  private fetchImpl: typeof fetch;

  constructor(baseUrl: string, token?: string, fetchImpl?: typeof fetch) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = token;
    this.fetchImpl = fetchImpl || (typeof globalThis !== 'undefined' ? globalThis.fetch.bind(globalThis) : undefined!) ;
  }

  /** Update the JWT token (e.g. after login) */
  setToken(token: string): void {
    this.token = token;
  }

  // ─── Auth ─────────────────────────────────────────────────────────────────

  /** Login and obtain a JWT token */
  async login(req: LoginRequest): Promise<LoginResponse> {
    const res = await this.request('POST', '/auth/login', formEncode({ ...req }));
    const data: LoginResponse = await res.json();
    this.token = data.token;
    return data;
  }

  /** Register a new user account */
  async registerUser(req: RegisterUserRequest): Promise<RegisterUserResponse> {
    const res = await this.request('POST', '/auth/user', formEncode({ ...req }));
    return res.json();
  }

  /** Register a new agent (requires AGENT_SECRET via admin endpoint) */
  async registerAgent(secret: string, req: RegisterAgentRequest): Promise<RegisterAgentResponse> {
    const res = await this.request('POST', '/auth/agent', formEncode({ ...req }), {
      'X-Agent-Secret': secret,
    });
    return res.json();
  }

  /** Change password for the authenticated user */
  async changePassword(req: ChangePasswordRequest): Promise<{ status: string }> {
    const res = await this.request('POST', '/auth/change-password', formEncode({ ...req }));
    return res.json();
  }

  // ─── Agents ───────────────────────────────────────────────────────────────

  /** List all available agents with live status */
  async listAgents(): Promise<Agent[]> {
    const res = await this.request('GET', '/agents');
    return res.json();
  }

  /** Admin: list all agents with connection details */
  async adminListAgents(): Promise<AdminAgent[]> {
    const res = await this.request('GET', '/admin/agents');
    return res.json();
  }

  // ─── Conversations ────────────────────────────────────────────────────────

  /** Create a new conversation with an agent */
  async createConversation(req: CreateConversationRequest): Promise<Conversation> {
    const res = await this.request('POST', '/conversations/create', formEncode({ ...req }));
    return res.json();
  }

  /** List conversations for the authenticated user */
  async listConversations(limit?: number, offset?: number, tag?: string): Promise<Conversation[]> {
    const params = new URLSearchParams();
    if (limit !== undefined) params.set('limit', String(limit));
    if (offset !== undefined) params.set('offset', String(offset));
    if (tag) params.set('tag', tag);
    const qs = params.toString() ? `?${params.toString()}` : '';
    const res = await this.request('GET', `/conversations/list${qs}`);
    return res.json();
  }

  /** Get messages for a conversation */
  async getMessages(conversationId: string, limit?: number, before?: string): Promise<Message[]> {
    const params = new URLSearchParams({ conversation_id: conversationId });
    if (limit !== undefined) params.set('limit', String(limit));
    if (before) params.set('before', before);
    const res = await this.request('GET', `/conversations/messages?${params.toString()}`);
    return res.json();
  }

  /** Delete a conversation (must be owner) */
  async deleteConversation(conversationId: string): Promise<{ status: string; conversation_id: string }> {
    const res = await this.request('DELETE', '/conversations/delete', formEncode({ conversation_id: conversationId }));
    return res.json();
  }

  /** Mark unread messages in a conversation as read */
  async markRead(conversationId: string): Promise<MarkReadResponse> {
    const res = await this.request('POST', '/conversations/mark-read', formEncode({ conversation_id: conversationId }));
    return res.json();
  }

  // ─── Messages ────────────────────────────────────────────────────────────

  /** Search messages by content */
  async searchMessages(query: string, limit?: number): Promise<SearchMessagesResponse> {
    const params = new URLSearchParams({ q: query });
    if (limit !== undefined) params.set('limit', String(limit));
    const res = await this.request('GET', `/messages/search?${params.toString()}`);
    return res.json();
  }

  /** Edit a message */
  async editMessage(req: EditMessageRequest): Promise<{ status: string }> {
    const res = await this.request('POST', '/messages/edit', formEncode({ ... req }));
    return res.json();
  }

  /** Delete a message */
  async deleteMessage(messageId: string): Promise<{ status: string }> {
    const res = await this.request('POST', '/messages/delete', formEncode({ message_id: messageId }));
    return res.json();
  }

  // ─── Reactions ────────────────────────────────────────────────────────────

  /** Toggle a reaction on a message */
  async react(messageId: string, emoji: string): Promise<ReactResponse> {
    const res = await this.request('POST', '/messages/react', formEncode({ message_id: messageId, emoji }));
    return res.json();
  }

  /** Get reactions for a message */
  async getReactions(messageId: string): Promise<Reaction[]> {
    const res = await this.request('GET', `/messages/reactions?message_id=${encodeURIComponent(messageId)}`);
    return res.json();
  }

  // ─── Tags ─────────────────────────────────────────────────────────────────

  /** Add a tag to a conversation */
  async addTag(req: TagRequest): Promise<{ status: string }> {
    const res = await this.request('POST', '/conversations/tags/add', formEncode({ ...req }));
    return res.json();
  }

  /** Remove a tag from a conversation */
  async removeTag(req: TagRequest): Promise<{ status: string }> {
    const res = await this.request('POST', '/conversations/tags/remove', formEncode({ ...req }));
    return res.json();
  }

  /** List tags for a conversation */
  async getTags(conversationId: string): Promise<Tag[]> {
    const res = await this.request('GET', `/conversations/tags?conversation_id=${encodeURIComponent(conversationId)}`);
    return res.json();
  }

  // ─── Presence ─────────────────────────────────────────────────────────────

  /** Get presence status for all agents */
  async getPresence(): Promise<PresenceEntry[]> {
    const res = await this.request('GET', '/presence');
    return res.json();
  }

  /** Get presence status for a specific user */
  async getUserPresence(userId?: string): Promise<PresenceEntry[]> {
    const params = userId ? `?user_id=${encodeURIComponent(userId)}` : '';
    const res = await this.request('GET', `/presence/user${params}`);
    return res.json();
  }

  // ─── Attachments ──────────────────────────────────────────────────────────

  /** Upload a file attachment */
  async uploadAttachment(conversationId: string, file: File | Blob, filename?: string, contentType?: string): Promise<UploadAttachmentResponse> {
    const formData = new FormData();
    formData.append('conversation_id', conversationId);
    if (typeof File !== 'undefined' && file instanceof File) {
      formData.append('file', file);
    } else {
      formData.append('file', file as Blob, filename || 'upload');
    }
    const headers: Record<string, string> = {};
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    const res = await this.fetchImpl(`${this.baseUrl}/attachments/upload`, {
      method: 'POST',
      headers,
      body: formData,
    });
    if (!res.ok) throw new ApiError(res.status, await res.text());
    return res.json();
  }

  /** Download an attachment by ID */
  getAttachmentUrl(attachmentId: string): string {
    return `${this.baseUrl}/attachments/${encodeURIComponent(attachmentId)}`;
  }

  /** List attachments for a message */
  async listAttachments(messageId: string): Promise<Attachment[]> {
    const res = await this.request('GET', `/messages/attachments?message_id=${encodeURIComponent(messageId)}`);
    return res.json();
  }

  // ─── E2E Encryption ──────────────────────────────────────────────────────

  /** Upload a key bundle for E2E encryption */
  async uploadKeyBundle(req: UploadKeyBundleRequest): Promise<{ status: string }> {
    const res = await this.request('POST', '/keys/upload', JSON.stringify(req), { 'Content-Type': 'application/json' });
    return res.json();
  }

  /** Get a key bundle for a user */
  async getKeyBundle(userId: string): Promise<KeyBundle> {
    const res = await this.request('GET', `/keys/bundle?user_id=${encodeURIComponent(userId)}`);
    return res.json();
  }

  /** Get one-time prekey count */
  async getOTPKCount(userId: string): Promise<{ count: number }> {
    const res = await this.request('GET', `/keys/otpk-count?user_id=${encodeURIComponent(userId)}`);
    return res.json();
  }

  /** Store an E2E encrypted message */
  async storeEncryptedMessage(req: StoreEncryptedMessageRequest): Promise<{ id: string }> {
    const res = await this.request('POST', '/messages/encrypted', JSON.stringify(req), { 'Content-Type': 'application/json' });
    return res.json();
  }

  /** Get E2E encrypted messages for a conversation */
  async getEncryptedMessages(conversationId: string, deviceId?: string, limit?: number, after?: string): Promise<EncryptedMessage[]> {
    const params = new URLSearchParams({ conversation_id: conversationId });
    if (deviceId) params.set('device_id', deviceId);
    if (limit !== undefined) params.set('limit', String(limit));
    if (after) params.set('after', after);
    const res = await this.request('GET', `/messages/encrypted/list?${params.toString()}`);
    return res.json();
  }

  // ─── Push Notifications ───────────────────────────────────────────────────

  /** Register a device token for push notifications */
  async registerDeviceToken(req: RegisterPushRequest): Promise<{ status: string }> {
    const res = await this.request('POST', '/push/register', JSON.stringify(req), { 'Content-Type': 'application/json' });
    return res.json();
  }

  /** Unregister a device token */
  async unregisterDeviceToken(req: UnregisterPushRequest): Promise<{ status: string }> {
    const res = await this.request('POST', '/push/unregister', JSON.stringify(req), { 'Content-Type': 'application/json' });
    return res.json();
  }

  /** Get the VAPID public key for web push subscription */
  async getVAPIDKey(): Promise<VAPIDKeyResponse> {
    const res = await this.request('GET', '/push/vapid-key');
    return res.json();
  }

  /** Subscribe to web push notifications */
  async webPushSubscribe(req: WebPushSubscribeRequest): Promise<WebPushSubscribeResponse> {
    const res = await this.request('POST', '/push/web-subscribe', JSON.stringify(req), { 'Content-Type': 'application/json' });
    return res.json();
  }

  /** Unsubscribe from web push notifications */
  async webPushUnsubscribe(req: WebPushUnsubscribeRequest): Promise<WebPushUnsubscribeResponse> {
    const res = await this.request('POST', '/push/web-unsubscribe', JSON.stringify(req), { 'Content-Type': 'application/json' });
    return res.json();
  }

  // ─── Admin ───────────────────────────────────────────────────────────────

  /** Get rate limit tier for a user */
  async getRateLimitTier(userId: string, adminSecret?: string): Promise<RateLimitInfo> {
    const params = new URLSearchParams({ user_id: userId });
    if (adminSecret) params.set('admin_secret', adminSecret);
    const res = await this.request('GET', `/admin/rate-limit/tier?${params.toString()}`);
    return res.json();
  }

  /** Set rate limit tier for a user */
  async setRateLimitTier(req: SetRateLimitTierRequest): Promise<{ status: string; user_id: string; tier: string }> {
    const res = await this.request('POST', '/admin/rate-limit/tier', formEncode({ ...req }));
    return res.json();
  }

  // ─── Health ───────────────────────────────────────────────────────────────

  /** Get server health status */
  async health(): Promise<HealthResponse> {
    const res = await this.fetchImpl(`${this.baseUrl}/health`);
    return res.json();
  }

  /** Get Prometheus metrics */
  async metrics(): Promise<string> {
    const res = await this.fetchImpl(`${this.baseUrl}/metrics`);
    return res.text();
  }

  // ─── Internal ────────────────────────────────────────────────────────────

  private async request(
    method: string,
    path: string,
    body?: string,
    extraHeaders?: Record<string, string>,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
      ...extraHeaders,
    };
    // Only set Content-Type for string bodies (skip for FormData)
    if (body && !extraHeaders?.['Content-Type']) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body || undefined,
    });
    if (!res.ok) {
      throw new ApiError(res.status, await res.text());
    }
    return res;
  }
}

/** Encode an object as application/x-www-form-urlencoded */
function formEncode(obj: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null) params.set(k, String(v));
  }
  return params.toString();
}

// Need to import Reaction type for getReactions return
import type { Reaction } from './types';