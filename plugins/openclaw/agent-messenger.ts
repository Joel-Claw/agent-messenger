import WebSocket from 'ws';

interface AgentMessengerConfig {
  serverUrl: string;
  apiKey: string;
  agentId: string;
}

interface Message {
  type: 'message';
  conversation_id: string;
  content: string;
  metadata?: Record<string, unknown>;
}

interface UserMessage {
  type: 'user_message';
  conversation_id: string;
  user_id: string;
  content: string;
  timestamp: string;
}

interface AgentMessage extends Message {
  agent_id: string;
  timestamp: string;
  message_id: string;
}

export class AgentMessengerPlugin {
  private ws: WebSocket | null = null;
  private config: AgentMessengerConfig;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private onUserMessage?: (msg: UserMessage) => void;

  constructor(config: AgentMessengerConfig) {
    this.config = config;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = `${this.config.serverUrl}/agent/connect?api_key=${this.config.apiKey}&agent_id=${this.config.agentId}`;

      this.ws = new WebSocket(url);

      this.ws.on('open', () => {
        console.log('[AgentMessenger] Connected to server');
        this.reconnectAttempts = 0;
        resolve();
      });

      this.ws.on('message', (data: Buffer) => {
        try {
          const msg = JSON.parse(data.toString());
          this.handleMessage(msg);
        } catch (err) {
          console.error('[AgentMessenger] Failed to parse message:', err);
        }
      });

      this.ws.on('close', () => {
        console.log('[AgentMessenger] Connection closed');
        this.reconnect();
      });

      this.ws.on('error', (err) => {
        console.error('[AgentMessenger] WebSocket error:', err);
        reject(err);
      });
    });
  }

  private handleMessage(msg: unknown): void {
    const message = msg as { type: string; [key: string]: unknown };

    switch (message.type) {
      case 'user_message':
        if (this.onUserMessage) {
          this.onUserMessage(message as UserMessage);
        }
        break;
      case 'error':
        console.error('[AgentMessenger] Server error:', message);
        break;
      default:
        console.log('[AgentMessenger] Unknown message type:', message.type);
    }
  }

  onMessage(callback: (msg: UserMessage) => void): void {
    this.onUserMessage = callback;
  }

  send(content: string, conversationId: string, metadata?: Record<string, unknown>): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.error('[AgentMessenger] Not connected');
      return;
    }

    const msg: Message = {
      type: 'message',
      conversation_id: conversationId,
      content,
      metadata,
    };

    this.ws.send(JSON.stringify(msg));
  }

  startTyping(conversationId: string): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    this.ws.send(JSON.stringify({
      type: 'typing',
      conversation_id: conversationId,
      typing: true,
    }));
  }

  stopTyping(conversationId: string): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    this.ws.send(JSON.stringify({
      type: 'typing',
      conversation_id: conversationId,
      typing: false,
    }));
  }

  setStatus(status: 'active' | 'idle' | 'busy' | 'offline', message?: string): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    this.ws.send(JSON.stringify({
      type: 'status',
      status,
      message,
    }));
  }

  private reconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[AgentMessenger] Max reconnect attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);

    console.log(`[AgentMessenger] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

    setTimeout(() => {
      this.connect().catch(err => {
        console.error('[AgentMessenger] Reconnect failed:', err);
      });
    }, delay);
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

// OpenClaw plugin registration
export default {
  name: 'agent-messenger',
  version: '0.1.0',
  description: 'Agent Messenger plugin for OpenClaw',
  init(config: AgentMessengerConfig) {
    return new AgentMessengerPlugin(config);
  },
};