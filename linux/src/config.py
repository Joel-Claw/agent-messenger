"""
Configuration management for Agent Messenger client.
"""

import json
import os
from pathlib import Path


CONFIG_DIR = Path.home() / '.config' / 'agent-messenger'
CONFIG_FILE = CONFIG_DIR / 'config.json'


class Config:
    """Application configuration."""

    def __init__(self, server_url='ws://localhost:8080', api_url='http://localhost:8080',
                 username='', password=''):
        self.server_url = server_url
        self.api_url = api_url
        self.username = username
        self.password = password

    @classmethod
    def load(cls) -> 'Config':
        """Load configuration from disk, creating defaults if not found."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                return cls(
                    server_url=data.get('server_url', 'ws://localhost:8080'),
                    api_url=data.get('api_url', 'http://localhost:8080'),
                    username=data.get('username', ''),
                    password=data.get('password', ''),
                )
            except (json.JSONDecodeError, OSError) as e:
                print(f'[AgentMessenger] Warning: Failed to load config: {e}')

        return cls()

    def save(self):
        """Save configuration to disk."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            'server_url': self.server_url,
            'api_url': self.api_url,
            'username': self.username,
            # Note: In production, password should be stored in keyring
            'password': self.password,
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)