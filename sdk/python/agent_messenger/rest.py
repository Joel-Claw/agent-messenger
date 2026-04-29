"""
Agent Messenger SDK — REST API client
"""

from __future__ import annotations

import json
from typing import Any, BinaryIO, Dict, List, Optional, Union
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from .types import (
    Agent,
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
    ReactRequest,
    ReactResponse,
    Reaction,
    RegisterAgentRequest,
    RegisterAgentResponse,
    RegisterUserRequest,
    RegisterUserResponse,
    SearchMessagesResponse,
    SetRateLimitTierRequest,
    StoreEncryptedMessageRequest,
    Tag,
    TagRequest,
    UploadAttachmentResponse,
    UploadKeyBundleRequest,
    UnregisterPushRequest,
    RegisterPushRequest,
    VAPIDKeyResponse,
    WebPushSubscribeRequest,
    WebPushSubscribeResponse,
    WebPushUnsubscribeRequest,
    WebPushUnsubscribeResponse,
)


class ApiError(Exception):
    """Raised when the API returns a non-2xx response."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"API error {status}: {body[:200]}")


class RestClient:
    """REST API client for Agent Messenger."""

    def __init__(self, base_url: str, token: str = ""):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def set_token(self, token: str) -> None:
        self.token = token

    # ─── Auth ──────────────────────────────────────────────────────────────

    def login(self, req: LoginRequest) -> LoginResponse:
        """Authenticate and get a JWT token."""
        data = self._post("/auth/login", {"username": req.username, "password": req.password})
        resp = LoginResponse(
            token=data["token"],
            user_id=data["user_id"],
            username=data["username"],
        )
        self.token = resp.token
        return resp

    def register_user(self, req: RegisterUserRequest) -> RegisterUserResponse:
        """Register a new user account."""
        data = self._post("/auth/user", {"username": req.username, "password": req.password})
        return RegisterUserResponse(
            user_id=data["user_id"],
            username=data["username"],
            status=data.get("status", "registered"),
            token=data.get("token", ""),
        )

    def register_agent(self, req: RegisterAgentRequest) -> RegisterAgentResponse:
        """Register a new AI agent (admin)."""
        data = self._post("/auth/agent", {
            "agent_id": req.agent_id,
            "agent_secret": req.agent_secret,
            "name": req.name,
            "model": req.model,
            "personality": req.personality,
            "specialty": req.specialty,
        }, admin=True)
        return RegisterAgentResponse(
            agent_id=data["agent_id"],
            name=data["name"],
            api_key=data["api_key"],
        )

    def change_password(self, req: ChangePasswordRequest) -> Dict[str, Any]:
        """Change the current user's password."""
        return self._post("/auth/change-password", {
            "current_password": req.current_password,
            "new_password": req.new_password,
        })

    # ─── Agents ────────────────────────────────────────────────────────────

    def list_agents(self) -> List[Agent]:
        """List all available agents."""
        data = self._get("/agents")
        return [Agent(
            agent_id=a["agent_id"],
            name=a["name"],
            model=a["model"],
            personality=a.get("personality", ""),
            specialty=a.get("specialty", ""),
            status=a.get("status", "offline"),
        ) for a in data]

    # ─── Conversations ─────────────────────────────────────────────────────

    def create_conversation(self, req: CreateConversationRequest) -> Conversation:
        """Create a new conversation with an agent."""
        data = self._post("/conversations/create", {"agent_id": req.agent_id})
        return Conversation(
            conversation_id=data["conversation_id"],
            user_id=data.get("user_id", ""),
            agent_id=data.get("agent_id", ""),
            created_at=data.get("created_at", ""),
        )

    def list_conversations(
        self,
        limit: int = 50,
        offset: int = 0,
        tag: str = "",
    ) -> List[Conversation]:
        """List the current user's conversations."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if tag:
            params["tag"] = tag
        data = self._get("/conversations/list", params)
        return [self._parse_conversation(c) for c in data]

    def get_messages(
        self,
        conversation_id: str,
        limit: int = 50,
        before: str = "",
    ) -> List[Message]:
        """Get messages in a conversation."""
        params: Dict[str, Any] = {"conversation_id": conversation_id, "limit": limit}
        if before:
            params["before"] = before
        data = self._get("/conversations/messages", params)
        return [self._parse_message(m) for m in data]

    def delete_conversation(self, conversation_id: str) -> Dict[str, Any]:
        """Delete a conversation."""
        return self._delete(f"/conversations/delete?conversation_id={conversation_id}")

    def mark_read(self, conversation_id: str) -> MarkReadResponse:
        """Mark all messages in a conversation as read."""
        data = self._post("/conversations/mark-read", {"conversation_id": conversation_id})
        return MarkReadResponse(
            status=data.get("status", ""),
            conversation_id=data.get("conversation_id", conversation_id),
            count=data.get("count", 0),
        )

    # ─── Messages ──────────────────────────────────────────────────────────

    def search_messages(self, query: str, limit: int = 20) -> SearchMessagesResponse:
        """Search messages across conversations."""
        data = self._get("/messages/search", {"q": query, "limit": limit})
        if isinstance(data, list):
            results = [self._parse_message(m) for m in data]
            return SearchMessagesResponse(results=results, total=len(results))
        results = [self._parse_message(m) for m in data.get("results", [])]
        total = data.get("total", len(results))
        return SearchMessagesResponse(results=results, total=total)

    def edit_message(self, req: EditMessageRequest) -> Dict[str, Any]:
        """Edit a message."""
        return self._post("/messages/edit", {
            "message_id": req.message_id,
            "content": req.content,
        })

    def delete_message(self, message_id: str) -> Dict[str, Any]:
        """Soft-delete a message."""
        return self._post("/messages/delete", {"message_id": message_id})

    # ─── Reactions ─────────────────────────────────────────────────────────

    def react(self, message_id: str, emoji: str) -> ReactResponse:
        """Toggle a reaction on a message."""
        data = self._post("/messages/react", {"message_id": message_id, "emoji": emoji})
        return ReactResponse(action=data.get("action", ""), emoji=data.get("emoji", emoji))

    def get_reactions(self, message_id: str) -> List[Reaction]:
        """Get reactions for a message."""
        data = self._get(f"/messages/reactions?message_id={message_id}")
        return [Reaction(emoji=r["emoji"], user_id=r["user_id"], created_at=r.get("created_at", ""))
                for r in data]

    # ─── Tags ──────────────────────────────────────────────────────────────

    def add_tag(self, req: TagRequest) -> Dict[str, Any]:
        """Add a tag to a conversation."""
        return self._post("/conversations/tags/add", {
            "conversation_id": req.conversation_id,
            "tag": req.tag,
        })

    def remove_tag(self, req: TagRequest) -> Dict[str, Any]:
        """Remove a tag from a conversation."""
        return self._post("/conversations/tags/remove", {
            "conversation_id": req.conversation_id,
            "tag": req.tag,
        })

    def get_tags(self, conversation_id: str) -> List[Tag]:
        """Get tags for a conversation."""
        data = self._get(f"/conversations/tags?conversation_id={conversation_id}")
        return [Tag(tag=t["tag"], created_at=t.get("created_at", "")) for t in data]

    # ─── Presence ──────────────────────────────────────────────────────────

    def get_presence(self) -> List[PresenceEntry]:
        """Get presence status for all agents."""
        data = self._get("/presence")
        return [PresenceEntry(
            agent_id=p["agent_id"],
            status=p.get("status", "offline"),
            last_seen=p.get("last_seen", ""),
        ) for p in data]

    def get_user_presence(self, user_id: str = "") -> List[PresenceEntry]:
        """Get presence for a specific user or all users."""
        params = {}
        if user_id:
            params["user_id"] = user_id
        data = self._get("/presence/user", params)
        return [PresenceEntry(
            agent_id=p.get("agent_id", ""),
            status=p.get("status", "offline"),
            last_seen=p.get("last_seen", ""),
        ) for p in data]

    # ─── Attachments ──────────────────────────────────────────────────────

    def upload_attachment(
        self,
        conversation_id: str,
        file: BinaryIO,
        filename: str = "",
        content_type: str = "",
    ) -> UploadAttachmentResponse:
        """Upload a file attachment."""
        import mimetypes
        if not filename:
            filename = getattr(file, "name", "upload")
        if not content_type:
            content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        boundary = "----AgentMessengerBoundary"
        body = f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="conversation_id"\r\n\r\n{conversation_id}\r\n'.encode()
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
        body += f"Content-Type: {content_type}\r\n\r\n".encode()
        body += file.read()
        body += f"\r\n--{boundary}--\r\n".encode()

        data = self._request("POST", "/attachments/upload", body=body, content_type=f"multipart/form-data; boundary={boundary}")
        return UploadAttachmentResponse(
            attachment_id=data["attachment_id"],
            filename=data.get("filename", filename),
            size=data.get("size", 0),
            content_type=data.get("content_type", content_type),
        )

    def get_attachment_url(self, attachment_id: str) -> str:
        """Get the download URL for an attachment."""
        return f"{self.base_url}/attachments/{attachment_id}"

    # ─── E2E Encryption ────────────────────────────────────────────────────

    def upload_key_bundle(self, req: UploadKeyBundleRequest) -> Dict[str, Any]:
        """Upload a Signal Protocol key bundle."""
        return self._post("/keys/upload", {
            "identity_key": req.identity_key,
            "signed_prekey": req.signed_prekey,
            "prekey_signature": req.prekey_signature,
            "one_time_prekeys": req.one_time_prekeys,
        })

    def get_key_bundle(self, user_id: str) -> KeyBundle:
        """Retrieve a key bundle for a user."""
        data = self._get(f"/keys/bundle?user_id={user_id}")
        return KeyBundle(
            identity_key=data["identity_key"],
            signed_prekey=data["signed_prekey"],
            prekey_signature=data.get("prekey_signature", ""),
            one_time_prekey=data.get("one_time_prekey", ""),
        )

    def store_encrypted_message(self, req: StoreEncryptedMessageRequest) -> Dict[str, Any]:
        """Store an encrypted message."""
        return self._post("/messages/encrypted", {
            "conversation_id": req.conversation_id,
            "ciphertext": req.ciphertext,
            "sender_device_id": req.sender_device_id,
            "message_type": req.message_type,
        })

    def get_encrypted_messages(
        self,
        conversation_id: str,
        limit: int = 50,
        before: str = "",
    ) -> List[EncryptedMessage]:
        """Get encrypted messages for a conversation."""
        params: Dict[str, Any] = {"conversation_id": conversation_id, "limit": limit}
        if before:
            params["before"] = before
        data = self._get("/messages/encrypted/list", params)
        return [EncryptedMessage(
            id=m["id"],
            conversation_id=m.get("conversation_id", ""),
            sender_device_id=m.get("sender_device_id", ""),
            ciphertext=m.get("ciphertext", ""),
            message_type=m.get("message_type", 1),
            timestamp=m.get("timestamp", ""),
        ) for m in data]

    # ─── Push Notifications ────────────────────────────────────────────────

    def register_device_token(self, req: RegisterPushRequest) -> Dict[str, Any]:
        """Register a device token for push notifications."""
        payload = {"device_token": req.device_token, "platform": req.platform}
        if req.device_id:
            payload["device_id"] = req.device_id
        return self._post("/push/register", payload)

    def unregister_device_token(self, req: UnregisterPushRequest) -> Dict[str, Any]:
        """Unregister a device token."""
        return self._post("/push/unregister", {"device_token": req.device_token})

    def get_vapid_key(self) -> VAPIDKeyResponse:
        """Get the VAPID public key for web push subscription."""
        data = self._get("/push/vapid-key")
        return VAPIDKeyResponse(public_key=data["public_key"])

    def web_push_subscribe(self, req: WebPushSubscribeRequest) -> WebPushSubscribeResponse:
        """Subscribe to web push notifications."""
        data = self._post("/push/web-subscribe", {
            "endpoint": req.endpoint,
            "keys": req.keys,
        })
        return WebPushSubscribeResponse(status=data["status"])

    def web_push_unsubscribe(self, req: WebPushUnsubscribeRequest) -> WebPushUnsubscribeResponse:
        """Unsubscribe from web push notifications."""
        data = self._post("/push/web-unsubscribe", {"endpoint": req.endpoint})
        return WebPushUnsubscribeResponse(status=data["status"])

    # ─── Admin ─────────────────────────────────────────────────────────────

    def get_rate_limit_tier(self, user_id: str) -> RateLimitInfo:
        """Get rate limit tier info for a user (admin)."""
        data = self._get(f"/admin/rate-limit/tier?user_id={user_id}", admin=True)
        return RateLimitInfo(
            user_id=data["user_id"],
            tier=data["tier"],
            burst=data.get("burst", 120),
            window_sec=data.get("window_sec", 60),
            remaining=data.get("remaining", 0),
        )

    def set_rate_limit_tier(self, req: SetRateLimitTierRequest) -> Dict[str, Any]:
        """Set rate limit tier for a user (admin)."""
        return self._post("/admin/rate-limit/tier", {
            "user_id": req.user_id,
            "tier": req.tier,
        }, admin=True)

    # ─── Health ────────────────────────────────────────────────────────────

    def health(self) -> HealthResponse:
        """Get server health status (no auth required)."""
        data = self._get("/health", auth=False)
        return HealthResponse(
            status=data.get("status", ""),
            uptime=data.get("uptime", ""),
            version=data.get("version", ""),
        )

    def metrics(self) -> Dict[str, Any]:
        """Get server metrics (no auth required)."""
        return self._get("/metrics", auth=False)

    # ─── Internal ──────────────────────────────────────────────────────────

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None, auth: bool = True, admin: bool = False) -> Any:
        query = ""
        if params:
            query = "?" + urlencode({k: v for k, v in params.items() if v is not None and v != ""})
        return self._request("GET", path + query, auth=auth, admin=admin)

    def _post(self, path: str, data: Dict[str, Any], auth: bool = True, admin: bool = False) -> Any:
        body = urlencode(data).encode()
        return self._request("POST", path, body=body, content_type="application/x-www-form-urlencoded", auth=auth, admin=admin)

    def _delete(self, path: str, auth: bool = True, admin: bool = False) -> Any:
        return self._request("DELETE", path, auth=auth, admin=admin)

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
        content_type: str = "",
        auth: bool = True,
        admin: bool = False,
    ) -> Any:
        url = self.base_url + path
        headers: Dict[str, str] = {}
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if content_type:
            headers["Content-Type"] = content_type
        if admin and self.token:
            headers["X-Admin-Key"] = self.token

        req = Request(url, data=body, headers=headers, method=method)
        try:
            with urlopen(req) as resp:
                resp_body = resp.read().decode("utf-8")
                if resp_body:
                    return json.loads(resp_body)
                return {}
        except HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            raise ApiError(e.code, body_text)

    # ─── Parse helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _parse_conversation(d: Dict[str, Any]) -> Conversation:
        last_msg = d.get("last_message")
        return Conversation(
            conversation_id=d["conversation_id"],
            user_id=d.get("user_id", ""),
            agent_id=d.get("agent_id", ""),
            created_at=d.get("created_at", ""),
            last_message=last_msg,
            unread_count=d.get("unread_count", 0),
            tags=d.get("tags", []),
        )

    @staticmethod
    def _parse_message(d: Dict[str, Any]) -> Message:
        return Message(
            message_id=d.get("message_id", ""),
            conversation_id=d.get("conversation_id", ""),
            user_id=d.get("user_id", ""),
            agent_id=d.get("agent_id", ""),
            content=d.get("content", ""),
            sender_type=d.get("sender_type", ""),
            sender_id=d.get("sender_id", ""),
            timestamp=d.get("timestamp", ""),
            edited_at=d.get("edited_at", ""),
            deleted=d.get("deleted", False),
            metadata=d.get("metadata", {}),
        )