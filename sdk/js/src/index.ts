/**
 * Agent Messenger SDK — Main entry point
 *
 * Provides a high-level AgentMessengerClient that combines REST API
 * and WebSocket messaging in a single, easy-to-use interface.
 */

export { RestClient, ApiError } from './rest';
export { ClientWS, AgentWS } from './websocket';

export type {
  Agent,
  AgentConfig,
  AdminAgent,
  Attachment,
  ChangePasswordRequest,
  ClientConfig,
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
  ReactRequest,
  ReactResponse,
  Reaction,
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
  WSChatData,
  WSConnectedData,
  WSErrorData,
  WSMessage,
  WSMessageSentData,
  WSReadReceiptData,
  WSReactionData,
  WSStatusData,
  WSTypingData,
  WSEventType,
  WSEventHandler,
} from './types';

import { RestClient } from './rest';
import { ClientWS, AgentWS } from './websocket';
import type {
  AgentConfig,
  ClientConfig,
  Conversation,
  LoginRequest,
  LoginResponse,
  RegisterUserRequest,
  RegisterUserResponse,
  WSChatData,
  WSConnectedData,
  WSErrorData,
  WSMessageSentData,
  WSReadReceiptData,
  WSStatusData,
  WSTypingData,
  WSReactionData,
  WSEventType,
  WSEventHandler,
} from './types';

/**
 * High-level client for users connecting to Agent Messenger.
 *
 * Provides both REST API access and real-time WebSocket messaging.
 *
 * @example
 * ```typescript
 * import { AgentMessengerClient } from '@anthropic/agent-messenger';
 *
 * const client = new AgentMessengerClient({ baseUrl: 'http://localhost:8080' });
 *
 * // Login
 * const { token } = await client.login({ username: 'alice', password: 'secret' });
 *
 * // List agents
 * const agents = await client.rest.listAgents();
 *
 * // Create a conversation
 * const conv = await client.rest.createConversation({ agent_id: agents[0].agent_id });
 *
 * // Connect WebSocket
 * await client.ws.connect();
 * client.ws.on('message', (data) => console.log('Got message:', data));
 *
 * // Send a message
 * client.ws.sendMessage(conv.conversation_id, 'Hello!');
 * ```
 */
export class AgentMessengerClient {
  /** REST API client for all HTTP endpoints */
  public readonly rest: RestClient;
  /** WebSocket client for real-time messaging */
  public readonly ws: ClientWS;

  constructor(config: ClientConfig) {
    this.rest = new RestClient(config.baseUrl, config.token, config.fetchImpl);
    this.ws = new ClientWS(config);
  }

  /** Login and automatically set the token on both REST and WS clients */
  async login(req: LoginRequest): Promise<LoginResponse> {
    const res = await this.rest.login(req);
    this.ws.setToken(res.token);
    return res;
  }

  /** Register a new user and automatically set the token */
  async register(req: RegisterUserRequest): Promise<RegisterUserResponse> {
    const res = await this.rest.registerUser(req);
    if (res.token) {
      this.rest.setToken(res.token);
      this.ws.setToken(res.token);
    }
    return res;
  }

  /** Convenience: connect WebSocket */
  async connect(): Promise<WSConnectedData> {
    return this.ws.connect();
  }

  /** Convenience: disconnect WebSocket */
  disconnect(): void {
    this.ws.disconnect();
  }

  /** Convenience: register event handler */
  on<T = unknown>(event: WSEventType, handler: WSEventHandler<T>): void {
    this.ws.on(event, handler);
  }

  /** Convenience: remove event handler */
  off<T = unknown>(event: WSEventType, handler: WSEventHandler<T>): void {
    this.ws.off(event, handler);
  }
}

/**
 * High-level client for AI agents connecting to Agent Messenger.
 *
 * Provides WebSocket connection for real-time message handling
 * with automatic reconnection.
 *
 * @example
 * ```typescript
 * import { AgentClient } from '@anthropic/agent-messenger';
 *
 * const agent = new AgentClient({
 *   baseUrl: 'http://localhost:8080',
 *   agentId: 'my-agent',
 *   agentSecret: process.env.AGENT_SECRET!,
 *   agentName: 'HelpBot',
 *   agentModel: 'gpt-4',
 * });
 *
 * await agent.connect();
 * agent.on('message', (data) => {
 *   console.log('User says:', data.content);
 *   agent.ws.sendMessage(data.conversation_id, 'I received your message!');
 * });
 * ```
 */
export class AgentClient {
  /** WebSocket client for real-time agent messaging */
  public readonly ws: AgentWS;

  constructor(config: AgentConfig) {
    this.ws = new AgentWS(config);
  }

  /** Connect to the server */
  async connect(): Promise<WSConnectedData> {
    return this.ws.connect();
  }

  /** Disconnect from the server */
  disconnect(): void {
    this.ws.disconnect();
  }

  /** Register event handler */
  on<T = unknown>(event: WSEventType, handler: WSEventHandler<T>): void {
    this.ws.on(event, handler);
  }

  /** Remove event handler */
  off<T = unknown>(event: WSEventType, handler: WSEventHandler<T>): void {
    this.ws.off(event, handler);
  }
}