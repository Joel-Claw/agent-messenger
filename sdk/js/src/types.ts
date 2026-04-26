/**
 * Agent Messenger SDK — Type definitions
 */

// ─── Auth ───────────────────────────────────────────────────────────────────

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user_id: string;
  username: string;
}

export interface RegisterUserRequest {
  username: string;
  password: string;
}

export interface RegisterUserResponse {
  user_id: string;
  username: string;
  status: string;
  token?: string;
}

export interface RegisterAgentRequest {
  agent_id: string;
  name?: string;
  model?: string;
  personality?: string;
  specialty?: string;
}

export interface RegisterAgentResponse {
  agent_id: string;
  status: string;
  model?: string;
  personality?: string;
  specialty?: string;
}

export interface ChangePasswordRequest {
  old_password: string;
  new_password: string;
}

// ─── Agents ─────────────────────────────────────────────────────────────────

export interface Agent {
  agent_id: string;
  name: string;
  model: string;
  personality: string;
  specialty: string;
  status: 'online' | 'offline' | 'busy' | 'idle';
}

export interface AdminAgent extends Agent {
  connected_at: string | null;
}

// ─── Conversations ──────────────────────────────────────────────────────────

export interface Conversation {
  conversation_id: string;
  user_id: string;
  agent_id: string;
  title: string | null;
  created_at: string;
  last_message: Message | null;
  unread_count: number;
  tags?: string[];
}

export interface CreateConversationRequest {
  agent_id: string;
  title?: string;
}

// ─── Messages ────────────────────────────────────────────────────────────────

export interface Message {
  message_id: string;
  conversation_id: string;
  sender_type: 'user' | 'agent';
  sender_id: string;
  content: string;
  created_at: string;
  read_at: string | null;
  edited: boolean;
  deleted: boolean;
}

export interface EditMessageRequest {
  message_id: string;
  content: string;
}

export interface DeleteMessageRequest {
  message_id: string;
}

export interface SearchMessagesResponse extends Array<Message> {}

// ─── Reactions ──────────────────────────────────────────────────────────────

export interface Reaction {
  id: string;
  message_id: string;
  user_id: string;
  emoji: string;
  created_at: string;
}

export interface ReactRequest {
  message_id: string;
  emoji: string;
}

export interface ReactResponse {
  action: 'added' | 'removed';
  emoji: string;
}

// ─── Tags ───────────────────────────────────────────────────────────────────

export interface Tag {
  tag: string;
  created_at: string;
}

export interface TagRequest {
  conversation_id: string;
  tag: string;
}

// ─── Presence ────────────────────────────────────────────────────────────────

export interface PresenceEntry {
  agent_id: string;
  status: 'online' | 'offline' | 'busy' | 'idle';
  last_seen: string | null;
}

// ─── Attachments ────────────────────────────────────────────────────────────

export interface Attachment {
  attachment_id: string;
  filename: string;
  url: string;
  size: number;
  content_type: string;
}

export interface UploadAttachmentResponse {
  attachment_id: string;
  filename: string;
  url: string;
  size: number;
  content_type: string;
}

// ─── E2E Encryption ─────────────────────────────────────────────────────────

export interface KeyBundle {
  identity_key: string;
  signed_prekey: string;
  prekey_signature: string;
  one_time_prekey: string | null;
}

export interface UploadKeyBundleRequest {
  identity_key: string;
  signed_prekey: string;
  prekey_signature: string;
  one_time_prekeys: string[];
}

export interface EncryptedMessage {
  id: string;
  conversation_id: string;
  sender_device_id: string;
  ciphertext: string;
  message_type: number;
  created_at: string;
}

export interface StoreEncryptedMessageRequest {
  conversation_id: string;
  ciphertext: string;
  sender_device_id: string;
  message_type?: number;
}

// ─── Push ───────────────────────────────────────────────────────────────────

export interface RegisterPushRequest {
  token: string;
  platform: 'apns' | 'fcm';
  device_id?: string;
}

export interface UnregisterPushRequest {
  token: string;
}

// ─── Rate Limiting ──────────────────────────────────────────────────────────

export interface RateLimitInfo {
  user_id: string;
  tier: 'free' | 'pro' | 'enterprise';
  burst: number;
  window_sec: number;
  remaining: number;
}

export interface SetRateLimitTierRequest {
  user_id: string;
  tier: 'free' | 'pro' | 'enterprise';
  admin_secret?: string;
}

// ─── Health ─────────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  uptime: string;
  version: string;
  connections: {
    agents: number;
    clients: number;
  };
  messages_routed: number;
  offline_queue_depth: number;
}

// ─── WebSocket ───────────────────────────────────────────────────────────────

export interface WSMessage<T = Record<string, unknown>> {
  type: string;
  data: T;
}

export interface WSConnectedData {
  id: string;
  status: string;
  protocol_version: string;
  supported_versions: string[];
  device_id?: string;
}

export interface WSChatData {
  conversation_id: string;
  content: string;
  sender_type: 'user' | 'agent';
  sender_id: string;
  recipient_id: string;
  timestamp?: string;
  attachment_ids?: string[];
  metadata?: Record<string, unknown>;
}

export interface WSTypingData {
  conversation_id: string;
  sender_type: string;
  sender_id: string;
}

export interface WSStatusData {
  conversation_id: string;
  sender_type: string;
  sender_id: string;
  status: string;
}

export interface WSReadReceiptData {
  conversation_id: string;
  read_by: string;
  count: number;
}

export interface WSReactionData {
  conversation_id: string;
  message_id: string;
  user_id: string;
  emoji: string;
  action: 'added' | 'removed';
}

export interface WSErrorData {
  error: string;
}

export interface WSMessageSentData {
  conversation_id: string;
  status: string;
}

export interface MarkReadResponse {
  status: string;
  conversation_id: string;
  count: number;
}

// ─── WebSocket Events ────────────────────────────────────────────────────────

export type WSEventType =
  | 'connected'
  | 'message'
  | 'message_sent'
  | 'typing'
  | 'status'
  | 'read_receipt'
  | 'reaction_added'
  | 'reaction_removed'
  | 'error'
  | 'disconnect'
  | 'reconnect';

export type WSEventHandler<T = unknown> = (data: T) => void;

// ─── SDK Config ─────────────────────────────────────────────────────────────

export interface ClientConfig {
  /** Base URL of the Agent Messenger server (e.g. http://localhost:8080) */
  baseUrl: string;
  /** JWT token for authentication (obtained via login or register) */
  token?: string;
  /** WebSocket protocol version (default: 'v1') */
  protocolVersion?: string;
  /** Device ID for multi-device sync (optional) */
  deviceId?: string;
  /** Auto-reconnect on disconnect (default: true) */
  autoReconnect?: boolean;
  /** Maximum reconnect attempts (default: 10) */
  maxReconnectAttempts?: number;
  /** Reconnect base delay in ms, doubles each attempt (default: 1000) */
  reconnectBaseDelay?: number;
  /** Custom fetch implementation (for Node.js < 18 or testing) */
  fetchImpl?: typeof fetch;
}

export interface AgentConfig {
  /** Base URL of the Agent Messenger server */
  baseUrl: string;
  /** Agent ID */
  agentId: string;
  /** Shared agent secret */
  agentSecret: string;
  /** Agent display name */
  agentName?: string;
  /** Agent model identifier */
  agentModel?: string;
  /** Agent personality description */
  agentPersonality?: string;
  /** Agent specialty */
  agentSpecialty?: string;
  /** WebSocket protocol version (default: 'v1') */
  protocolVersion?: string;
  /** Auto-reconnect on disconnect (default: true) */
  autoReconnect?: boolean;
  /** Maximum reconnect attempts (default: 10) */
  maxReconnectAttempts?: number;
  /** Reconnect base delay in ms (default: 1000) */
  reconnectBaseDelay?: number;
  /** Custom WebSocket implementation (for Node.js vs browser) */
  wsImpl?: new (url: string) => WebSocket;
}