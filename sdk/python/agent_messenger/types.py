"""
Agent Messenger SDK — Type definitions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union


# ─── Auth ─────────────────────────────────────────────────────────────────────

@dataclass
class LoginRequest:
    username: str
    password: str


@dataclass
class LoginResponse:
    token: str
    user_id: str
    username: str


@dataclass
class RegisterUserRequest:
    username: str
    password: str


@dataclass
class RegisterUserResponse:
    user_id: str
    username: str
    status: str
    token: str = ""


@dataclass
class ChangePasswordRequest:
    current_password: str
    new_password: str


# ─── Agents ───────────────────────────────────────────────────────────────────

@dataclass
class Agent:
    agent_id: str
    name: str
    model: str
    personality: str
    specialty: str
    status: str


@dataclass
class RegisterAgentRequest:
    agent_id: str
    agent_secret: str
    name: str
    model: str
    personality: str = ""
    specialty: str = ""


@dataclass
class RegisterAgentResponse:
    agent_id: str
    name: str
    api_key: str


@dataclass
class AdminAgent:
    agent_id: str
    name: str
    model: str
    personality: str
    specialty: str
    status: str
    connected_at: str = ""
    ip_address: str = ""


# ─── Conversations ────────────────────────────────────────────────────────────

@dataclass
class Conversation:
    conversation_id: str
    user_id: str = ""
    agent_id: str = ""
    created_at: str = ""
    last_message: Optional[Dict[str, Any]] = None
    unread_count: int = 0
    tags: List[str] = field(default_factory=list)


@dataclass
class CreateConversationRequest:
    agent_id: str


# ─── Messages ─────────────────────────────────────────────────────────────────

@dataclass
class Message:
    message_id: str = ""
    conversation_id: str = ""
    user_id: str = ""
    agent_id: str = ""
    content: str = ""
    sender_type: str = ""
    sender_id: str = ""
    timestamp: str = ""
    edited_at: str = ""
    deleted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EditMessageRequest:
    message_id: str
    content: str


@dataclass
class SearchMessagesResponse:
    results: List[Message] = field(default_factory=list)
    total: int = 0


@dataclass
class MarkReadResponse:
    status: str = ""
    conversation_id: str = ""
    count: int = 0


# ─── Reactions ────────────────────────────────────────────────────────────────

@dataclass
class ReactRequest:
    message_id: str
    emoji: str


@dataclass
class ReactResponse:
    action: str
    emoji: str


@dataclass
class Reaction:
    emoji: str
    user_id: str
    created_at: str = ""


# ─── Tags ──────────────────────────────────────────────────────────────────────

@dataclass
class Tag:
    tag: str
    created_at: str = ""


@dataclass
class TagRequest:
    conversation_id: str
    tag: str


# ─── Presence ──────────────────────────────────────────────────────────────────

@dataclass
class PresenceEntry:
    agent_id: str
    status: str
    last_seen: str = ""


# ─── Attachments ──────────────────────────────────────────────────────────────

@dataclass
class UploadAttachmentResponse:
    attachment_id: str
    filename: str
    size: int
    content_type: str


# ─── E2E Encryption ───────────────────────────────────────────────────────────

@dataclass
class UploadKeyBundleRequest:
    identity_key: str
    signed_prekey: str
    prekey_signature: str
    one_time_prekeys: List[str] = field(default_factory=list)


@dataclass
class KeyBundle:
    identity_key: str
    signed_prekey: str
    prekey_signature: str
    one_time_prekey: str = ""


@dataclass
class StoreEncryptedMessageRequest:
    conversation_id: str
    ciphertext: str
    sender_device_id: str = ""
    message_type: int = 1


@dataclass
class EncryptedMessage:
    id: str
    conversation_id: str
    sender_device_id: str
    ciphertext: str
    message_type: int = 1
    timestamp: str = ""


# ─── Push ──────────────────────────────────────────────────────────────────────

@dataclass
class RegisterPushRequest:
    device_token: str
    platform: str  # "ios", "android", or "web"
    device_id: Optional[str] = None


@dataclass
class UnregisterPushRequest:
    device_token: str


# ─── Web Push ────────────────────────────────────────────────────────────────


@dataclass
class WebPushSubscribeRequest:
    endpoint: str
    keys: Dict[str, str]  # {"p256dh": "...", "auth": "..."}


@dataclass
class WebPushUnsubscribeRequest:
    endpoint: str


@dataclass
class VAPIDKeyResponse:
    public_key: str


@dataclass
class WebPushSubscribeResponse:
    status: str


@dataclass
class WebPushUnsubscribeResponse:
    status: str


# ─── Rate Limiting ────────────────────────────────────────────────────────────

@dataclass
class RateLimitInfo:
    user_id: str
    tier: str
    burst: int
    window_sec: int
    remaining: int


@dataclass
class SetRateLimitTierRequest:
    user_id: str
    tier: str


# ─── Health ────────────────────────────────────────────────────────────────────

@dataclass
class HealthResponse:
    status: str
    uptime: str = ""
    version: str = ""


# ─── WebSocket Message Types ──────────────────────────────────────────────────

@dataclass
class WSConnectedData:
    id: str
    status: str = "connected"
    protocol_version: str = "v1"
    supported_versions: List[str] = field(default_factory=lambda: ["v1"])
    device_id: str = ""


@dataclass
class WSChatData:
    conversation_id: str
    content: str = ""
    sender_type: str = ""
    sender_id: str = ""
    message_id: str = ""
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WSMessageSentData:
    message_id: str
    conversation_id: str = ""
    timestamp: str = ""


@dataclass
class WSTypingData:
    conversation_id: str
    sender_type: str = ""
    sender_id: str = ""


@dataclass
class WSStatusData:
    conversation_id: str = ""
    sender_type: str = ""
    sender_id: str = ""
    status: str = ""


@dataclass
class WSReadReceiptData:
    conversation_id: str
    read_by: str = ""
    count: int = 0


@dataclass
class WSReactionData:
    message_id: str
    emoji: str = ""
    user_id: str = ""
    action: str = ""


@dataclass
class WSErrorData:
    error: str = ""


@dataclass
class WSMessage:
    type: str
    data: Dict[str, Any] = field(default_factory=dict)


# ─── SDK Config ───────────────────────────────────────────────────────────────

@dataclass
class ClientConfig:
    base_url: str
    token: str = ""
    device_id: str = ""
    protocol_version: str = "v1"
    auto_reconnect: bool = True
    max_reconnect_attempts: int = 10
    reconnect_base_delay: float = 1.0


@dataclass
class AgentConfig:
    base_url: str
    agent_id: str
    agent_secret: str
    agent_name: str = ""
    agent_model: str = ""
    agent_personality: str = ""
    agent_specialty: str = ""
    protocol_version: str = "v1"
    auto_reconnect: bool = True
    max_reconnect_attempts: int = 10
    reconnect_base_delay: float = 1.0


# ─── Event Types ───────────────────────────────────────────────────────────────

WSEventType = str  # One of: connected, message, message_sent, typing, status, read_receipt, reaction_added, reaction_removed, error, disconnect, reconnect