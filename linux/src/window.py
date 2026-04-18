"""
Main application window for Agent Messenger Linux client.

GTK4 + Adwaita UI with:
- Agent list sidebar
- Chat view with message bubbles
- Login form
- Typing indicator
- Dark mode support
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gio, Gtk, Adw, GLib, Pango

import json
import requests
from datetime import datetime

from src.styles import CSS


class MainWindow(Adw.ApplicationWindow):
    """Main application window."""

    def __init__(self, config, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self.client = None
        self.agents = []
        self.conversations = []
        self.current_conversation_id = None
        self.typing_timeout_id = None

        self.set_title('Agent Messenger')
        self.set_default_size(800, 600)

        # Load CSS
        self._load_css()

        # Build UI
        self._build_ui()

        # Load agents if authenticated
        if self.config.email and self.config.password:
            GLib.idle_add(self._authenticate_and_load)

    def _load_css(self):
        """Load application CSS."""
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS.encode('utf-8'))
        Gtk.StyleContext.add_provider_for_display(
            self.get_display(),
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

    def set_client(self, client):
        """Set the WebSocket client and wire up callbacks."""
        self.client = client
        self.client.set_on_message(self._on_message)
        self.client.set_on_typing(self._on_typing)
        self.client.set_on_status(self._on_status)

    def set_notifications(self, notifications):
        """Set the notification manager."""
        self.notifications = notifications

    def _build_ui(self):
        """Build the main UI layout."""
        # Main layout: sidebar + chat
        self.panels = Adw.OverlaySplitView()
        self.set_content(self.panels)

        # Sidebar: agent list
        self.sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.sidebar_box.set_margin_top(12)
        self.sidebar_box.set_margin_bottom(12)
        self.sidebar_box.set_margin_start(12)
        self.sidebar_box.set_margin_end(12)

        sidebar_label = Gtk.Label(label='Agents')
        sidebar_label.add_css_class('title-4')
        self.sidebar_box.append(sidebar_label)

        # Agent list
        self.agent_list = Gtk.ListBox()
        self.agent_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.agent_list.connect('row-selected', self._on_agent_selected)
        self.sidebar_box.append(self.agent_list)

        # Login form in sidebar
        self.login_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.login_box.set_margin_top(12)

        self.email_entry = Adw.EntryRow(title='Email')
        self.email_entry.set_text(self.config.email)
        self.login_box.append(self.email_entry)

        self.password_entry = Adw.EntryRow(title='Password')
        self.password_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self.password_entry.set_visibility(False)
        self.password_entry.set_text(self.config.password)
        self.login_box.append(self.password_entry)

        self.login_button = Gtk.Button(label='Connect')
        self.login_button.add_css_class('suggested-action')
        self.login_button.connect('clicked', self._on_login_clicked)
        self.login_box.append(self.login_button)

        self.login_status = Gtk.Label(label='')
        self.login_box.append(self.login_status)

        self.sidebar_box.append(self.login_box)

        # Status indicator
        self.status_label = Gtk.Label(label='Disconnected')
        self.status_label.add_css_class('dim-label')
        self.status_label.add_css_class('caption')
        self.sidebar_box.append(self.status_label)

        self.panels.set_sidebar(self.sidebar_box)

        # Content: chat view
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # Header bar
        header = Adw.HeaderBar()
        self.conversation_title = Gtk.Label(label='Select an agent')
        self.conversation_title.add_css_class('title-4')
        header.set_title_widget(self.conversation_title)

        # Menu button for sidebar toggle
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name('open-menu-symbolic')
        menu_button.set_tooltip_text('Menu')
        header.pack_end(menu_button)

        # Sidebar toggle
        self.sidebar_toggle = Gtk.ToggleButton()
        self.sidebar_toggle.set_icon_name('sidebar-show-symbolic')
        self.sidebar_toggle.set_tooltip_text('Toggle Sidebar')
        self.sidebar_toggle.connect('toggled', self._on_sidebar_toggle)
        header.pack_start(self.sidebar_toggle)

        content_box.append(header)

        # Chat area
        self.chat_scrolled = Gtk.ScrolledWindow()
        self.chat_scrolled.set_vexpand(True)
        self.chat_scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        self.chat_list = Gtk.ListBox()
        self.chat_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.chat_list.add_css_class('chat-list')
        self.chat_scrolled.set_child(self.chat_list)

        content_box.append(self.chat_scrolled)

        # Typing indicator
        self.typing_label = Gtk.Label(label='')
        self.typing_label.add_css_class('dim-label')
        self.typing_label.add_css_class('caption')
        content_box.append(self.typing_label)

        # Message input
        input_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        input_box.set_margin_top(6)
        input_box.set_margin_bottom(6)
        input_box.set_margin_start(12)
        input_box.set_margin_end(12)

        self.message_entry = Gtk.Entry()
        self.message_entry.set_hexpand(True)
        self.message_entry.set_placeholder_text('Type a message...')
        self.message_entry.connect('activate', self._on_send_message)
        input_box.append(self.message_entry)

        self.send_button = Gtk.Button(icon_name='send-symbolic')
        self.send_button.add_css_class('suggested-action')
        self.send_button.connect('clicked', self._on_send_message)
        input_box.append(self.send_button)

        content_box.append(input_box)

        self.panels.set_content(content_box)

        # Initially show login
        self._update_ui_state()

    def _update_ui_state(self):
        """Update UI based on connection state."""
        authenticated = bool(self.config.email and self.config.password)
        self.message_entry.set_sensitive(authenticated)
        self.send_button.set_sensitive(authenticated)

    def _on_sidebar_toggle(self, button):
        """Toggle sidebar visibility."""
        self.panels.set_show_sidebar(button.get_active())

    def _on_login_clicked(self, button):
        """Handle login button click."""
        email = self.email_entry.get_text().strip()
        password = self.password_entry.get_text().strip()

        if not email or not password:
            self.login_status.set_text('Please enter email and password')
            return

        self.config.email = email
        self.config.password = password
        self.config.save()

        self.login_button.set_sensitive(False)
        self.login_status.set_text('Connecting...')

        # Authenticate in background
        GLib.idle_add(self._authenticate_and_load)

    def _authenticate_and_load(self):
        """Authenticate with server and load data."""
        try:
            resp = requests.post(
                f'{self.config.api_url}/auth/login',
                data={'email': self.config.email, 'password': self.config.password},
            )

            if resp.status_code != 200:
                error = resp.json().get('error', 'Unknown error')
                self.login_status.set_text(f'Login failed: {error}')
                self.login_button.set_sensitive(True)
                return False

            data = resp.json()
            self._jwt_token = data.get('token')
            self._user_id = data.get('user_id')

            # Save credentials
            self.config.save()
            self.login_status.set_text('Connected!')
            self.login_button.set_sensitive(False)

            # Load agents
            self._load_agents()

            # Connect WebSocket
            if self.client:
                self.client.connect()

            self._update_ui_state()
            return False

        except Exception as e:
            self.login_status.set_text(f'Error: {e}')
            self.login_button.set_sensitive(True)
            return False

    def _load_agents(self):
        """Load available agents from server."""
        try:
            headers = {'Authorization': f'Bearer {self._jwt_token}'}
            resp = requests.get(f'{self.config.api_url}/agents', headers=headers)

            if resp.status_code == 200:
                data = resp.json()
                self.agents = data if isinstance(data, list) else data.get('agents', [])
                self._refresh_agent_list()
            else:
                print(f'[AgentMessenger] Failed to load agents: {resp.status_code}')
        except Exception as e:
            print(f'[AgentMessenger] Error loading agents: {e}')

    def _refresh_agent_list(self):
        """Refresh the agent list UI."""
        # Clear existing rows
        while self.agent_list.get_first_child():
            self.agent_list.remove(self.agent_list.get_first_child())

        for agent in self.agents:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            box.set_margin_top(6)
            box.set_margin_bottom(6)

            name_label = Gtk.Label(label=agent.get('name', agent.get('id', 'Unknown')))
            name_label.set_halign(Gtk.Align.START)
            name_label.add_css_class('heading')
            box.append(name_label)

            # Status indicator
            status = agent.get('status', 'offline')
            status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
            status_dot = Gtk.Label(label='●')
            if status == 'online':
                status_dot.add_css_class('success')
            elif status == 'busy':
                status_dot.add_css_class('warning')
            else:
                status_dot.add_css_class('dim-label')
            status_box.append(status_dot)
            status_text = Gtk.Label(label=status.capitalize())
            status_text.add_css_class('caption')
            status_text.add_css_class('dim-label')
            status_box.append(status_text)
            box.append(status_box)

            if agent.get('specialty'):
                specialty = Gtk.Label(label=agent.get('specialty'))
                specialty.add_css_class('caption')
                specialty.add_css_class('dim-label')
                box.append(specialty)

            row.set_child(box)
            row.agent_data = agent
            self.agent_list.append(row)

    def _on_agent_selected(self, list_box, row):
        """Handle agent selection."""
        if not row:
            return

        agent = row.agent_data
        agent_id = agent.get('id', '')
        agent_name = agent.get('name', 'Unknown Agent')

        self.conversation_title.set_text(agent_name)

        # Create or find conversation
        self._create_conversation(agent_id, agent_name)

    def _create_conversation(self, agent_id, agent_name):
        """Create or find a conversation with an agent."""
        try:
            headers = {'Authorization': f'Bearer {self._jwt_token}'}
            resp = requests.post(
                f'{self.config.api_url}/conversations/create',
                data={'user_id': self._user_id, 'agent_id': agent_id},
                headers=headers,
            )

            if resp.status_code == 200:
                data = resp.json()
                self.current_conversation_id = data.get('id')
                self._load_conversation_history(self.current_conversation_id)
            else:
                print(f'[AgentMessenger] Failed to create conversation: {resp.status_code}')
        except Exception as e:
            print(f'[AgentMessenger] Error creating conversation: {e}')

    def _load_conversation_history(self, conversation_id):
        """Load message history for a conversation."""
        # Clear existing messages
        while self.chat_list.get_first_child():
            self.chat_list.remove(self.chat_list.get_first_child())

        try:
            headers = {'Authorization': f'Bearer {self._jwt_token}'}
            params = {'conversation_id': conversation_id}
            resp = requests.get(
                f'{self.config.api_url}/conversations/messages',
                params=params,
                headers=headers,
            )

            if resp.status_code == 200:
                messages = resp.json()
                for msg in messages:
                    self._add_message_bubble(msg.get('content', ''), msg.get('sender_type', 'user'))
                self._scroll_to_bottom()
        except Exception as e:
            print(f'[AgentMessenger] Error loading history: {e}')

    def _add_message_bubble(self, text, sender_type='user'):
        """Add a message bubble to the chat."""
        row = Gtk.ListBoxRow()
        row.set_selectable(False)
        row.set_activatable(False)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        box.set_margin_start(12)
        box.set_margin_end(12)

        bubble = Gtk.Label(label=text)
        bubble.set_wrap(True)
        bubble.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        bubble.set_max_width_chars(60)
        bubble.set_xalign(0 if sender_type == 'agent' else 1)
        bubble.set_halign(Gtk.Align.START if sender_type == 'agent' else Gtk.Align.END)

        if sender_type == 'agent':
            bubble.add_css_class('agent-bubble')
        else:
            bubble.add_css_class('user-bubble')

        # Timestamp
        timestamp = Gtk.Label(label=datetime.now().strftime('%H:%M'))
        timestamp.add_css_class('caption')
        timestamp.add_css_class('dim-label')
        timestamp.set_halign(Gtk.Align.START if sender_type == 'agent' else Gtk.Align.END)

        box.append(bubble)
        box.append(timestamp)
        row.set_child(box)

        self.chat_list.append(row)

    def _scroll_to_bottom(self):
        """Scroll chat to the bottom."""
        GLib.idle_add(self._do_scroll_to_bottom)

    def _do_scroll_to_bottom(self):
        """Actually perform the scroll."""
        adj = self.chat_scrolled.get_vadjustment()
        adj.set_value(adj.get_upper())
        return False

    def _on_send_message(self, widget):
        """Send a message."""
        text = self.message_entry.get_text().strip()
        if not text or not self.current_conversation_id or not self.client:
            return

        if self.client.send_message(self.current_conversation_id, text):
            self._add_message_bubble(text, 'user')
            self.message_entry.set_text('')
            self._scroll_to_bottom()

    def _on_message(self, msg):
        """Handle incoming message from server (called from WS thread)."""
        GLib.idle_add(self._handle_message, msg)

    def _handle_message(self, msg):
        """Handle message on the UI thread."""
        content = msg.get('content', '')
        conv_id = msg.get('conversation_id', '')

        if conv_id == self.current_conversation_id:
            self._add_message_bubble(content, 'agent')
            self._scroll_to_bottom()
        else:
            # Show desktop notification if window is not focused or different conversation
            if self.notifications:
                agent_name = msg.get('agent_id', 'Agent')
                self.notifications.send_message_notification(agent_name, content, conv_id)

        return False

    def _on_typing(self, conversation_id, typing):
        """Handle typing indicator."""
        GLib.idle_add(self._handle_typing, conversation_id, typing)

    def _handle_typing(self, conversation_id, typing):
        """Handle typing on UI thread."""
        if conversation_id == self.current_conversation_id:
            if typing:
                self.typing_label.set_text('Agent is typing...')
            else:
                self.typing_label.set_text('')
        return False

    def _on_status(self, agent_id, status):
        """Handle agent status update."""
        GLib.idle_add(self._handle_status, agent_id, status)

    def _handle_status(self, agent_id, status):
        """Handle status on UI thread."""
        # Refresh agent list to show updated status
        self._refresh_agent_list()
        return False

    def on_connected(self):
        """Called when WebSocket connects."""
        self.status_label.set_text('Connected')
        self.status_label.remove_css_class('error')
        self.status_label.add_css_class('success')

    def on_disconnected(self):
        """Called when WebSocket disconnects."""
        self.status_label.set_text('Disconnected')
        self.status_label.remove_css_class('success')
        self.status_label.add_css_class('error')