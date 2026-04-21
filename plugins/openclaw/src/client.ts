/**
 * Agent Messenger WebSocket client.
 * Connects to the Agent Messenger server and handles message routing.
 */
import WebSocket from 'ws';

export interface AgentMessengerConfig {
  serverUrl: string;
  agentSecret: string;
  agentId: string;
  agentName?: string;
  agentModel?: string;
  agentPersonality?: string;
  agentSpecialty?: string;
}

export interface UserMessage {
  type: 'user_message';
  conversation_id: string;
  user_id: string;
  content: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface ConversationCreated {
  type: 'conversation_created';
  conversation_id: string;
  user_id: string;
  agent_id: string;
}

export interface ServerMessage {
  type: string;
  data?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface MessageSent {
  type: 'message_sent';
  message_id: string;
  conversation_id: string;
  timestamp: string;
}

type MessageHandler = (msg: UserMessage) => void;
type ConversationHandler = (msg: ConversationCreated) => void;
type ErrorHandler = (err: Error) => void;
type ConnectHandler = () => void;
type DisconnectHandler = () => void;

export class AgentMessengerClient {
  private ws: WebSocket | null = null;
  private config: AgentMessengerConfig;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private messageHandlers: MessageHandler[] = [];
  private conversationHandlers: ConversationHandler[] = [];
  private errorHandlers: ErrorHandler[] = [];
  private connectHandlers: ConnectHandler[] = [];
  private disconnectHandlers: DisconnectHandler[] = [];

  constructor(config: AgentMessengerConfig) {
    this.config = config;
  }

  get connected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const params = new URLSearchParams({
        agent_secret: this.config.agentSecret,
        agent_id: this.config.agentId,
      });
      if (this.config.agentName) params.set('name', this.config.agentName);
      if (this.config.agentModel) params.set('model', this.config.agentModel);
      if (this.config.agentPersonality) params.set('personality', this.config.agentPersonality);
      if (this.config.agentSpecialty) params.set('specialty', this.config.agentSpecialty);
      const url = `${this.config.serverUrl}/agent/connect?${params.toString()}`;

      this.ws = new WebSocket(url);

      const connectTimeout = setTimeout(() => {
        if (this.ws) {
          this.ws.terminate();
          this.ws = null;
        }
        reject(new Error('Connection timeout'));
      }, 10000);

      this.ws.on('open', () => {
        clearTimeout(connectTimeout);
        this.reconnectAttempts = 0;
        this.connectHandlers.forEach(h => h());
        resolve();
      });

      this.ws.on('message', (data: Buffer) => {
        try {
          const msg = JSON.parse(data.toString()) as ServerMessage;
          this.handleMessage(msg);
        } catch (err) {
          console.error('[AgentMessenger] Failed to parse message:', err);
        }
      });

      this.ws.on('close', (code, reason) => {
        clearTimeout(connectTimeout);
        console.log(`[AgentMessenger] Connection closed: ${code} ${reason.toString()}`);
        this.disconnectHandlers.forEach(h => h());
        this.scheduleReconnect();
      });

      this.ws.on('error', (err) => {
        clearTimeout(connectTimeout);
        console.error('[AgentMessenger] WebSocket error:', err.message);
        this.errorHandlers.forEach(h => h(err));
        reject(err);
      });
    });
  }

  private handleMessage(msg: ServerMessage): void {
    const msgType = msg.type;

    switch (msgType) {
      case 'user_message':
        this.messageHandlers.forEach(h => h(msg as unknown as UserMessage));
        break;
      case 'conversation_created':
        this.conversationHandlers.forEach(h => h(msg as unknown as ConversationCreated));
        break;
      case 'error':
        const errMsg = (msg.data as Record<string, string>)?.error || 'Unknown server error';
        console.error('[AgentMessenger] Server error:', errMsg);
        this.errorHandlers.forEach(h => h(new Error(errMsg)));
        break;
      case 'connected':
        console.log('[AgentMessenger] Server confirmed connection');
        break;
      case 'message_sent':
        // Confirmation that our message was received by the server
        break;
      default:
        console.log('[AgentMessenger] Unknown message type:', msgType);
    }
  }

  onMessage(handler: MessageHandler): void {
    this.messageHandlers.push(handler);
  }

  onConversation(handler: ConversationHandler): void {
    this.conversationHandlers.push(handler);
  }

  onError(handler: ErrorHandler): void {
    this.errorHandlers.push(handler);
  }

  onConnect(handler: ConnectHandler): void {
    this.connectHandlers.push(handler);
  }

  onDisconnect(handler: DisconnectHandler): void {
    this.disconnectHandlers.push(handler);
  }

  /**
   * Send a text message to a conversation.
   */
  sendMessage(content: string, conversationId: string, metadata?: Record<string, unknown>): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.error('[AgentMessenger] Not connected, cannot send message');
      return;
    }

    const msg = {
      type: 'message',
      data: {
        conversation_id: conversationId,
        content,
        metadata,
      },
    };

    this.ws.send(JSON.stringify(msg));
  }

  /**
   * Send typing indicator.
   */
  sendTyping(conversationId: string, typing: boolean): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    this.ws.send(JSON.stringify({
      type: 'typing',
      data: {
        conversation_id: conversationId,
        typing,
      },
    }));
  }

  /**
   * Send agent status update.
   */
  sendStatus(status: 'active' | 'idle' | 'busy' | 'offline', message?: string): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    this.ws.send(JSON.stringify({
      type: 'status',
      data: {
        status,
        message,
      },
    }));
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[AgentMessenger] Max reconnect attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);

    console.log(`[AgentMessenger] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

    this.reconnectTimer = setTimeout(() => {
      this.connect().catch(err => {
        console.error('[AgentMessenger] Reconnect failed:', err.message);
      });
    }, delay);
  }

  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectAttempts = this.maxReconnectAttempts; // Prevent auto-reconnect
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}