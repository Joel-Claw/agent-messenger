"""
Agent Messenger SDK — High-level client classes.

Provides AgentMessengerClient (for users) and AgentClient (for AI agents)
that combine REST + WebSocket into a single easy-to-use interface.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Union

from .rest import RestClient
from .websocket import ClientWS, AgentWS
from .types import (
    AgentConfig,
    ClientConfig,
    LoginRequest,
    LoginResponse,
    RegisterUserRequest,
    RegisterUserResponse,
    WSConnectedData,
)


class AgentMessengerClient:
    """
    High-level client for Agent Messenger.
    Combines REST API and WebSocket messaging.
    """

    def __init__(self, base_url: str = "", token: str = "", **kwargs: Any):
        config = ClientConfig(
            base_url=base_url,
            token=token,
            **{k: v for k, v in kwargs.items() if k in (
                "device_id", "protocol_version", "auto_reconnect",
                "max_reconnect_attempts", "reconnect_base_delay",
            )},
        )
        self.rest = RestClient(base_url, token)
        self.ws = ClientWS(config)

    def login(self, username: str, password: str) -> LoginResponse:
        """Login and auto-set the token on both REST and WS clients."""
        result = self.rest.login(LoginRequest(username=username, password=password))
        self.ws.set_token(result.token)
        return result

    def register(self, username: str, password: str) -> RegisterUserResponse:
        """Register a new user."""
        return self.rest.register_user(RegisterUserRequest(username=username, password=password))

    def connect(self) -> WSConnectedData:
        """Connect the WebSocket for real-time messaging."""
        return self.ws.connect()

    def disconnect(self) -> None:
        """Disconnect the WebSocket."""
        self.ws.disconnect()

    def on(self, event: str, handler: Callable) -> None:
        """Register an event handler."""
        self.ws.on(event, handler)

    def off(self, event: str, handler: Callable) -> None:
        """Remove an event handler."""
        self.ws.off(event, handler)


class AgentClient:
    """
    High-level client for AI agents.
    Uses WebSocket for real-time message handling.
    """

    def __init__(self, base_url: str = "", agent_id: str = "",
                 agent_secret: str = "", **kwargs: Any):
        config = AgentConfig(
            base_url=base_url,
            agent_id=agent_id,
            agent_secret=agent_secret,
            **{k: v for k, v in kwargs.items() if k in (
                "agent_name", "agent_model", "agent_personality",
                "agent_specialty", "protocol_version", "auto_reconnect",
                "max_reconnect_attempts", "reconnect_base_delay",
            )},
        )
        self.ws = AgentWS(config)

    def connect(self) -> WSConnectedData:
        """Connect to the server as an agent."""
        return self.ws.connect()

    def disconnect(self) -> None:
        """Disconnect from the server."""
        self.ws.disconnect()

    def on(self, event: str, handler: Callable) -> None:
        """Register an event handler."""
        self.ws.on(event, handler)

    def off(self, event: str, handler: Callable) -> None:
        """Remove an event handler."""
        self.ws.off(event, handler)