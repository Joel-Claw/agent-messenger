"""
CSS styles for Agent Messenger GTK4 client.
"""

CSS = """
/* Global styles */
window {
  background-color: @window_bg_color;
}

/* Chat list styling */
.chat-list {
  background-color: transparent;
}

.chat-list row {
  padding: 2px 0;
}

/* Message bubbles */
.agent-bubble {
  background-color: @card_bg_color;
  color: @window_fg_color;
  padding: 10px 14px;
  border-radius: 12px 12px 12px 4px;
}

.user-bubble {
  background-color: @accent_bg_color;
  color: @accent_fg_color;
  padding: 10px 14px;
  border-radius: 12px 12px 4px 12px;
}

/* Status colors */
.success {
  color: @success_color;
}

.warning {
  color: @warning_color;
}

.error {
  color: @error_color;
}

.dim-label {
  opacity: 0.6;
}

/* Sidebar styling */
.sidebar-row {
  padding: 8px 12px;
  border-radius: 8px;
  margin: 2px 0;
}

.sidebar-row:hover {
  background-color: alpha(@accent_bg_color, 0.1);
}

.sidebar-row:selected {
  background-color: alpha(@accent_bg_color, 0.2);
}

/* Login form */
.login-box {
  padding: 12px;
}

/* Message input */
.message-entry {
  border-radius: 20px;
  padding: 8px 16px;
}

/* Typing indicator animation */
@keyframes pulse {
  0% { opacity: 0.4; }
  50% { opacity: 1.0; }
  100% { opacity: 0.4; }
}

.typing-indicator {
  animation: pulse 1.5s ease-in-out infinite;
}
"""