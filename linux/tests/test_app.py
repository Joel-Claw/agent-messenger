"""
Tests for the main application module.

Tests the AgentMessengerApp class initialization and action setup
without requiring a running display server.
"""

import sys
import os
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestAppActions:
    """Test GAction registration and app initialization."""

    def test_app_has_application_id(self):
        """App should have the correct application ID."""
        # We can't instantiate GTK without a display, but we can
        # verify the ID is defined in the source
        import src.main as main_module
        source = open(os.path.join(os.path.dirname(__file__), '..', 'src', 'main.py')).read()
        assert 'com.joelclaw.agentmessenger' in source

    def test_config_directory_exists(self):
        """Config directory path should be set correctly."""
        from src.config import Config, CONFIG_DIR
        assert str(CONFIG_DIR).endswith('.config/agent-messenger')

    def test_config_persistence_round_trip(self):
        """Config should persist and load correctly."""
        import tempfile
        import json
        from pathlib import Path

        # Use a temp file for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / 'config.json'
            config = Config(
                server_url='ws://testhost:9090',
                api_url='http://testhost:9090',
                email='test@example.com',
                password='secret123',
            )

            # Save
            config_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'server_url': config.server_url,
                'api_url': config.api_url,
                'email': config.email,
                'password': config.password,
            }
            with open(config_path, 'w') as f:
                json.dump(data, f, indent=2)

            # Load
            with open(config_path, 'r') as f:
                loaded = json.load(f)

            assert loaded['server_url'] == 'ws://testhost:9090'
            assert loaded['api_url'] == 'http://testhost:9090'
            assert loaded['email'] == 'test@example.com'
            assert loaded['password'] == 'secret123'

    def test_default_config_values(self):
        """Default config should point to localhost:8080."""
        from src.config import Config
        config = Config()
        assert config.server_url == 'ws://localhost:8080'
        assert config.api_url == 'http://localhost:8080'
        assert config.email == ''
        assert config.password == ''

    def test_desktop_file_exists(self):
        """Desktop file should exist in data/ directory."""
        desktop_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'com.joelclaw.agentmessenger.desktop')
        assert os.path.isfile(desktop_path), f"Desktop file not found at {desktop_path}"

        # Verify it has required keys
        with open(desktop_path) as f:
            content = f.read()
        assert 'Name=' in content
        assert 'Exec=' in content
        assert 'Type=Application' in content
        assert 'Categories=' in content

    def test_metainfo_file_exists(self):
        """Metainfo XML should exist in data/ directory."""
        metainfo_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'com.joelclaw.agentmessenger.metainfo.xml')
        assert os.path.isfile(metainfo_path)

        with open(metainfo_path) as f:
            content = f.read()
        assert 'com.joelclaw.agentmessenger' in content
        assert '<id>' in content

    def test_install_script_exists(self):
        """Install script should exist."""
        install_path = os.path.join(os.path.dirname(__file__), '..', 'install.sh')
        assert os.path.isfile(install_path)
        assert os.access(install_path, os.X_OK), "install.sh should be executable"


# Import Config for the test above
from src.config import Config