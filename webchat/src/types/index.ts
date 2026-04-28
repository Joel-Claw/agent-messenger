export interface Agent {
  id: string;
  name: string;
  model: string;
  personality: string;
  specialty: string;
  status: 'online' | 'offline' | 'busy' | 'idle';
}

export interface LastMessage {
  content: string;
  sender_type: string;
  created_at: string;
}

export interface Conversation {
  id: string;
  user_id: string;
  agent_id: string;
  created_at: string;
  updated_at: string;
  last_message?: LastMessage;
  unread_count?: number;
}

export interface Reaction {
  id: string;
  message_id: string;
  user_id: string;
  emoji: string;
  created_at: string;
}

export interface Message {
  id: string;
  conversation_id: string;
  sender: 'user' | 'agent';
  content: string;
  timestamp: string;
  type: 'text' | 'typing' | 'status';
  attachment_ids?: string[];
  attachments?: Attachment[];
  edited_at?: string;
  is_deleted?: boolean;
  read_at?: string;
  reactions?: Reaction[];
}

export interface Attachment {
  id: string;
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
  url: string;
  created_at: string;
}

export interface UploadResult {
  id: string;
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
  url: string;
  created_at: string;
}

export type UploadStatus = 'idle' | 'uploading' | 'done' | 'error';

export interface ServerMessage {
  type: string;
  data?: Record<string, unknown>;
  conversation_id?: string;
  content?: string;
  agent_id?: string;
  message_id?: string;
  timestamp?: string;
  emoji?: string;
}

export interface AuthResponse {
  token: string;
  user_id: string;
}

export interface AgentPresence {
  id: string;
  name: string;
  online: boolean;
  status: string;
  last_seen?: string;
}

export interface AgentListResponse {
  agents: Agent[];
}