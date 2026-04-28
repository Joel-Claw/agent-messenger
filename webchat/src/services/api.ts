import type { Agent, AgentPresence, Conversation, Message, Reaction, UploadResult } from '../types';

const WS_BASE = process.env.REACT_APP_WS_URL || `ws://${window.location.hostname}:8080`;
const API_BASE = process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8080`;

export { WS_BASE, API_BASE };

export async function login(username: string, password: string): Promise<{ token: string; user_id: string; username: string }> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Login failed' }));
    throw new Error(err.error || 'Login failed');
  }
  return res.json();
}

export async function register(username: string, password: string): Promise<{ user_id: string; username: string }> {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Registration failed' }));
    throw new Error(err.error || 'Registration failed');
  }
  return res.json();
}

export async function getAgents(token: string): Promise<Agent[]> {
  const res = await fetch(`${API_BASE}/agents`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch agents');
  const data = await res.json();
  return data.agents || data;
}

export async function getConversations(token: string): Promise<Conversation[]> {
  const res = await fetch(`${API_BASE}/conversations`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch conversations');
  return res.json();
}

export async function getMessages(token: string, conversationId: string): Promise<Message[]> {
  const res = await fetch(`${API_BASE}/conversations/${conversationId}/messages`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch messages');
  return res.json();
}

export async function uploadAttachment(token: string, file: File, onProgress?: (percent: number) => void): Promise<UploadResult> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const formData = new FormData();
    formData.append('file', file);

    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable && onProgress) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    });

    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch {
          reject(new Error('Invalid response from server'));
        }
      } else {
        try {
          const err = JSON.parse(xhr.responseText);
          reject(new Error(err.error || `Upload failed (${xhr.status})`));
        } catch {
          reject(new Error(`Upload failed (${xhr.status})`));
        }
      }
    });

    xhr.addEventListener('error', () => reject(new Error('Network error during upload')));
    xhr.addEventListener('abort', () => reject(new Error('Upload cancelled')));

    xhr.open('POST', `${API_BASE}/attachments/upload`);
    xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    xhr.send(formData);
  });
}

export function getAttachmentUrl(attachmentId: string): string {
  return `${API_BASE}/attachments/${attachmentId}`;
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

// --- Reactions ---

export async function toggleReaction(token: string, messageId: string, emoji: string): Promise<{ status: string; reaction?: Reaction; message_id?: string; emoji?: string }> {
  const res = await fetch(`${API_BASE}/messages/react`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: `message_id=${encodeURIComponent(messageId)}&emoji=${encodeURIComponent(emoji)}`,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Reaction failed' }));
    throw new Error(err.error || 'Reaction failed');
  }
  return res.json();
}

export async function getMessageReactions(token: string, messageId: string): Promise<Reaction[]> {
  const res = await fetch(`${API_BASE}/messages/reactions?message_id=${encodeURIComponent(messageId)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch reactions');
  return res.json();
}

// --- Message Edit/Delete ---

export async function editMessage(token: string, messageId: string, content: string): Promise<{ status: string; message_id: string; content: string; edited_at: string }> {
  const res = await fetch(`${API_BASE}/messages/edit`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: `message_id=${encodeURIComponent(messageId)}&content=${encodeURIComponent(content)}`,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Edit failed' }));
    throw new Error(err.error || 'Edit failed');
  }
  return res.json();
}

export async function deleteMessage(token: string, messageId: string): Promise<{ status: string; message_id: string }> {
  const res = await fetch(`${API_BASE}/messages/delete`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: `message_id=${encodeURIComponent(messageId)}`,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Delete failed' }));
    throw new Error(err.error || 'Delete failed');
  }
  return res.json();
}

// --- Read Receipts ---

export async function markConversationRead(token: string, conversationId: string): Promise<{ status: string; count: number }> {
  const res = await fetch(`${API_BASE}/conversations/mark-read`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: `conversation_id=${encodeURIComponent(conversationId)}`,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Mark read failed' }));
    throw new Error(err.error || 'Mark read failed');
  }
  return res.json();
}

// --- Presence ---

export async function getPresence(token: string): Promise<AgentPresence[]> {
  const res = await fetch(`${API_BASE}/presence`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch presence');
  return res.json();
}

export function isImageContentType(ct: string): boolean {
  return ct.startsWith('image/');
}

export function isAudioContentType(ct: string): boolean {
  return ct.startsWith('audio/');
}

export function isVideoContentType(ct: string): boolean {
  return ct.startsWith('video/');
}