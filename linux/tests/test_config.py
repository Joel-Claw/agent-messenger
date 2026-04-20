"""Tests for config module."""

import json
import os
import tempfile
from unittest import mock

import pytest
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.config import Config


class TestConfig:
    """Test Config class."""

    def test_default_values(self):
        """Config should have sensible defaults."""
        config = Config()
        assert config.server_url == 'ws://localhost:8080'
        assert config.api_url == 'http://localhost:8080'
        assert config.username == ''
        assert config.password == ''

    def test_custom_values(self):
        """Config should accept custom values."""
        config = Config(
            server_url='ws://example.com:9090',
            api_url='http://example.com:9090',
            username='testuser',
            password='secret',
        )
        assert config.server_url == 'ws://example.com:9090'
        assert config.api_url == 'http://example.com:9090'
        assert config.username == 'testuser'
        assert config.password == 'secret'

    def test_save_and_load(self, tmp_path):
        """Config should persist to disk and load back."""
        import src.config as config_module
        original_dir = config_module.CONFIG_DIR
        config_module.CONFIG_DIR = tmp_path / 'agent-messenger-test'
        config_module.CONFIG_FILE = config_module.CONFIG_DIR / 'config.json'

        try:
            config = Config(
                server_url='ws://test:8080',
                api_url='http://test:8080',
                username='myuser',
                password='pass123',
            )
            config.save()

            loaded = Config.load()
            assert loaded.server_url == 'ws://test:8080'
            assert loaded.api_url == 'http://test:8080'
            assert loaded.username == 'myuser'
            assert loaded.password == 'pass123'
        finally:
            config_module.CONFIG_DIR = original_dir
            config_module.CONFIG_FILE = original_dir / 'config.json'

    def test_load_missing_file(self, tmp_path):
        """Loading a missing config file should return defaults."""
        import src.config as config_module
        original_file = config_module.CONFIG_FILE
        config_module.CONFIG_FILE = tmp_path / 'nonexistent.json'

        try:
            config = Config.load()
            assert config.server_url == 'ws://localhost:8080'
            assert config.username == ''
        finally:
            config_module.CONFIG_FILE = original_file

    def test_load_corrupted_file(self, tmp_path):
        """Loading a corrupted config file should return defaults."""
        import src.config as config_module
        original_dir = config_module.CONFIG_DIR
        config_module.CONFIG_DIR = tmp_path / 'agent-messenger-test'
        config_module.CONFIG_FILE = config_module.CONFIG_DIR / 'config.json'

        try:
            config_module.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            config_module.CONFIG_FILE.write_text('{invalid json')

            config = Config.load()
            assert config.server_url == 'ws://localhost:8080'
        finally:
            config_module.CONFIG_DIR = original_dir
            config_module.CONFIG_FILE = original_dir / 'config.json'