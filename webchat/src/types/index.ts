export interface Agent {
  id: string;
  name: string;
  model: string;
  personality: string;
  specialty: string;
  status: 'online' | 'offline' | 'busy' | 'idle';
}

export interface Conversation {
  id: string;
  user_id: string;
  agent_id: string;
  created_at: string;
  updated_at: string;
}

export interface Message {
  id: string;
  conversation_id: string;
  sender: 'user' | 'agent';
  content: string;
  timestamp: string;
  type: 'text' | 'typing' | 'status';
}

export interface ServerMessage {
  type: string;
  data?: Record<string, unknown>;
  conversation_id?: string;
  content?: string;
  agent_id?: string;
  message_id?: string;
  timestamp?: string;
}

export interface AuthResponse {
  token: string;
  user_id: string;
}

export interface AgentListResponse {
  agents: Agent[];
}