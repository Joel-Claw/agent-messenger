/**
 * Agent Messenger SDK — WebSocket client for real-time messaging
 */

import type {
  AgentConfig,
  ClientConfig,
  WSEventType,
  WSEventHandler,
  WSChatData,
  WSConnectedData,
  WSErrorData,
  WSMessage,
  WSMessageSentData,
  WSReadReceiptData,
  WSReactionData,
  WSStatusData,
  WSTypingData,
} from './types';

/**
 * Browser-compatible WebSocket client for user messaging.
 * Connects as a client to /client/connect.
 */
export class ClientWS {
  private config: Required<Pick<ClientConfig, 'baseUrl' | 'token'>> & Pick<ClientConfig, 'deviceId' | 'protocolVersion'> & {
    autoReconnect: boolean;
    maxReconnectAttempts: number;
    reconnectBaseDelay: number;
  };
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private handlers: Map<WSEventType, Set<WSEventHandler>> = new Map();
  private wsImpl?: new (url: string, protocols?: string[]) => WebSocket;

  constructor(config: ClientConfig) {
    this.config = {
      baseUrl: config.baseUrl,
      token: config.token || '',
      deviceId: config.deviceId,
      protocolVersion: config.protocolVersion || 'v1',
      autoReconnect: config.autoReconnect ?? true,
      maxReconnectAttempts: config.maxReconnectAttempts ?? 10,
      reconnectBaseDelay: config.reconnectBaseDelay ?? 1000,
    };
    // Use custom WebSocket impl if provided (for Node.js environments)
    this.wsImpl = (config as any).wsImpl;
  }

  /** Update the JWT token (use after login) */
  setToken(token: string): void {
    this.config.token = token;
  }

  /** Connect to the server */
  connect(): Promise<WSConnectedData> {
    return new Promise((resolve, reject) => {
      this.disconnect();

      const params = new URLSearchParams({ token: this.config.token });
      if (this.config.deviceId) params.set('device_id', this.config.deviceId);

      const wsUrl = this.config.baseUrl
        .replace(/^http/, 'ws')
        .replace(/\/+$/, '') + `/client/connect?${params.toString()}`;

      const WS = this.wsImpl || WebSocket;
      this.ws = new WS(wsUrl, [this.config.protocolVersion!]) as WebSocket;

      const connectTimeout = setTimeout(() => {
        this.ws?.close();
        this.ws = null;
        reject(new Error('Connection timeout'));
      }, 10000);

      this.ws.onopen = () => {
        // Connection established, but wait for server welcome
      };

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const msg: WSMessage = JSON.parse(typeof event.data === 'string' ? event.data : '');
          this.handleMessage(msg, resolve, reject, connectTimeout);
        } catch {
          // Ignore malformed messages
        }
      };

      this.ws.onerror = (event: Event) => {
        clearTimeout(connectTimeout);
        reject(new Error('WebSocket connection error'));
      };

      this.ws.onclose = () => {
        clearTimeout(connectTimeout);
        this.emit('disconnect', null);
        if (this.config.autoReconnect) {
          this.scheduleReconnect();
        }
      };
    });
  }

  /** Disconnect from the server */
  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectAttempts = 0;
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
    }
  }

  /** Check if currently connected */
  get connected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  /** Send a chat message */
  sendMessage(conversationId: string, content: string, metadata?: Record<string, unknown>): void {
    this.send({
      type: 'message',
      data: {
        conversation_id: conversationId,
        content,
        ...(metadata ? { metadata } : {}),
      },
    });
  }

  /** Send a typing indicator */
  sendTyping(conversationId: string): void {
    this.send({
      type: 'typing',
      data: { conversation_id: conversationId },
    });
  }

  /** Send a status update */
  sendStatus(conversationId: string, status: string): void {
    this.send({
      type: 'status',
      data: { conversation_id: conversationId, status },
    });
  }

  /** Register an event handler */
  on<T = unknown>(event: WSEventType, handler: WSEventHandler<T>): void {
    if (!this.handlers.has(event)) this.handlers.set(event, new Set());
    this.handlers.get(event)!.add(handler as WSEventHandler);
  }

  /** Remove an event handler */
  off<T = unknown>(event: WSEventType, handler: WSEventHandler<T>): void {
    this.handlers.get(event)?.delete(handler as WSEventHandler);
  }

  // ─── Internal ────────────────────────────────────────────────────────────

  private handleMessage(
    msg: WSMessage,
    resolve: (data: WSConnectedData) => void,
    reject: (err: Error) => void,
    connectTimeout: ReturnType<typeof setTimeout>,
  ): void {
    switch (msg.type) {
      case 'connected':
        clearTimeout(connectTimeout);
        this.reconnectAttempts = 0;
        this.emit('connected', msg.data as unknown as WSConnectedData);
        resolve(msg.data as unknown as WSConnectedData);
        break;
      case 'message':
        this.emit('message', msg.data as unknown as WSChatData);
        break;
      case 'message_sent':
        this.emit('message_sent', msg.data as unknown as WSMessageSentData);
        break;
      case 'typing':
        this.emit('typing', msg.data as unknown as WSTypingData);
        break;
      case 'status':
        this.emit('status', msg.data as unknown as WSStatusData);
        break;
      case 'read_receipt':
        this.emit('read_receipt', msg.data as unknown as WSReadReceiptData);
        break;
      case 'reaction_added':
        this.emit('reaction_added', msg.data as unknown as WSReactionData);
        break;
      case 'reaction_removed':
        this.emit('reaction_removed', msg.data as unknown as WSReactionData);
        break;
      case 'error':
        const errData = msg.data as unknown as WSErrorData;
        this.emit('error', errData);
        break;
      default:
        // Forward unknown types as generic events
        this.emit(msg.type as WSEventType, msg.data);
    }
  }

  private emit(event: WSEventType, data: unknown): void {
    this.handlers.get(event)?.forEach(h => h(data));
  }

  private send(msg: WSMessage): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected');
    }
    this.ws.send(JSON.stringify(msg));
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.config.maxReconnectAttempts) {
      this.emit('error', { error: 'Max reconnect attempts reached' });
      return;
    }
    this.reconnectAttempts++;
    const delay = Math.min(this.config.reconnectBaseDelay * Math.pow(2, this.reconnectAttempts - 1), 30000);
    this.reconnectTimer = setTimeout(() => {
      this.connect().catch(() => {
        // Will retry again via onclose handler
      });
    }, delay);
  }
}

/**
 * WebSocket client for AI agents.
 * Connects as an agent to /agent/connect.
 */
export class AgentWS {
  private config: Required<Pick<AgentConfig, 'baseUrl' | 'agentId' | 'agentSecret'>> &
    Pick<AgentConfig, 'agentName' | 'agentModel' | 'agentPersonality' | 'agentSpecialty' | 'protocolVersion'> & {
    autoReconnect: boolean;
    maxReconnectAttempts: number;
    reconnectBaseDelay: number;
  };
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private handlers: Map<WSEventType, Set<WSEventHandler>> = new Map();
  private wsImpl?: new (url: string, protocols?: string[]) => WebSocket;

  constructor(config: AgentConfig) {
    this.config = {
      baseUrl: config.baseUrl,
      agentId: config.agentId,
      agentSecret: config.agentSecret,
      agentName: config.agentName,
      agentModel: config.agentModel,
      agentPersonality: config.agentPersonality,
      agentSpecialty: config.agentSpecialty,
      protocolVersion: config.protocolVersion || 'v1',
      autoReconnect: config.autoReconnect ?? true,
      maxReconnectAttempts: config.maxReconnectAttempts ?? 10,
      reconnectBaseDelay: config.reconnectBaseDelay ?? 1000,
    };
    this.wsImpl = (config as any).wsImpl;
  }

  /** Connect to the server */
  connect(): Promise<WSConnectedData> {
    return new Promise((resolve, reject) => {
      this.disconnect();

      const params = new URLSearchParams({
        agent_id: this.config.agentId,
        agent_secret: this.config.agentSecret,
      });
      if (this.config.agentName) params.set('name', this.config.agentName);
      if (this.config.agentModel) params.set('model', this.config.agentModel);
      if (this.config.agentPersonality) params.set('personality', this.config.agentPersonality);
      if (this.config.agentSpecialty) params.set('specialty', this.config.agentSpecialty);

      const wsUrl = this.config.baseUrl
        .replace(/^http/, 'ws')
        .replace(/\/+$/, '') + `/agent/connect?${params.toString()}`;

      const WS = this.wsImpl || WebSocket;
      this.ws = new WS(wsUrl, [this.config.protocolVersion!]) as WebSocket;

      const connectTimeout = setTimeout(() => {
        this.ws?.close();
        this.ws = null;
        reject(new Error('Connection timeout'));
      }, 10000);

      this.ws.onopen = () => {
        // Wait for server welcome message
      };

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const msg: WSMessage = JSON.parse(typeof event.data === 'string' ? event.data : '');
          this.handleMessage(msg, resolve, reject, connectTimeout);
        } catch {
          // Ignore malformed messages
        }
      };

      this.ws.onerror = () => {
        clearTimeout(connectTimeout);
        reject(new Error('WebSocket connection error'));
      };

      this.ws.onclose = () => {
        clearTimeout(connectTimeout);
        this.emit('disconnect', null);
        if (this.config.autoReconnect) {
          this.scheduleReconnect();
        }
      };
    });
  }

  /** Disconnect from the server */
  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectAttempts = 0;
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
    }
  }

  /** Check if currently connected */
  get connected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  /** Send a chat message to a conversation */
  sendMessage(conversationId: string, content: string, metadata?: Record<string, unknown>): void {
    this.send({
      type: 'message',
      data: {
        conversation_id: conversationId,
        content,
        ...(metadata ? { metadata } : {}),
      },
    });
  }

  /** Send a typing indicator */
  sendTyping(conversationId: string): void {
    this.send({
      type: 'typing',
      data: { conversation_id: conversationId },
    });
  }

  /** Send agent status update */
  sendStatus(status: 'active' | 'idle' | 'busy' | 'offline', conversationId?: string): void {
    const data: Record<string, string> = { status };
    if (conversationId) data.conversation_id = conversationId;
    this.send({ type: 'status', data });
  }

  /** Register an event handler */
  on<T = unknown>(event: WSEventType, handler: WSEventHandler<T>): void {
    if (!this.handlers.has(event)) this.handlers.set(event, new Set());
    this.handlers.get(event)!.add(handler as WSEventHandler);
  }

  /** Remove an event handler */
  off<T = unknown>(event: WSEventType, handler: WSEventHandler<T>): void {
    this.handlers.get(event)?.delete(handler as WSEventHandler);
  }

  // ─── Internal ────────────────────────────────────────────────────────────

  private handleMessage(
    msg: WSMessage,
    resolve: (data: WSConnectedData) => void,
    reject: (err: Error) => void,
    connectTimeout: ReturnType<typeof setTimeout>,
  ): void {
    switch (msg.type) {
      case 'connected':
        clearTimeout(connectTimeout);
        this.reconnectAttempts = 0;
        this.emit('connected', msg.data as unknown as WSConnectedData);
        resolve(msg.data as unknown as WSConnectedData);
        break;
      case 'message':
        this.emit('message', msg.data as unknown as WSChatData);
        break;
      case 'message_sent':
        this.emit('message_sent', msg.data as unknown as WSMessageSentData);
        break;
      case 'typing':
        this.emit('typing', msg.data as unknown as WSTypingData);
        break;
      case 'status':
        this.emit('status', msg.data as unknown as WSStatusData);
        break;
      case 'read_receipt':
        this.emit('read_receipt', msg.data as unknown as WSReadReceiptData);
        break;
      case 'error':
        this.emit('error', msg.data as unknown as WSErrorData);
        break;
      default:
        this.emit(msg.type as WSEventType, msg.data);
    }
  }

  private emit(event: WSEventType, data: unknown): void {
    this.handlers.get(event)?.forEach(h => h(data));
  }

  private send(msg: WSMessage): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected');
    }
    this.ws.send(JSON.stringify(msg));
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.config.maxReconnectAttempts) {
      this.emit('error', { error: 'Max reconnect attempts reached' });
      return;
    }
    this.reconnectAttempts++;
    const delay = Math.min(this.config.reconnectBaseDelay * Math.pow(2, this.reconnectAttempts - 1), 30000);
    this.reconnectTimer = setTimeout(() => {
      this.connect().catch(() => {});
    }, delay);
  }
}