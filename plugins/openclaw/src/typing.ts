/**
 * Agent Messenger typing and status indicators.
 *
 * Provides functions to:
 * - Send typing indicators when the agent is processing
 * - Update agent status (active, idle, busy, offline)
 * - Integrate with OpenClaw's reply dispatcher for automatic typing management
 */
import { getClient } from './runtime.js';

/**
 * Send a typing indicator for a conversation.
 * Call when the agent starts processing a message.
 */
export function startTyping(conversationId: string): void {
  const client = getClient();
  if (client?.connected) {
    client.sendTyping(conversationId, true);
  }
}

/**
 * Stop typing indicator for a conversation.
 * Call when the agent finishes processing.
 */
export function stopTyping(conversationId: string): void {
  const client = getClient();
  if (client?.connected) {
    client.sendTyping(conversationId, false);
  }
}

/**
 * Update the agent's status on the server.
 */
export function setAgentStatus(
  status: 'active' | 'idle' | 'busy' | 'offline',
  message?: string,
): void {
  const client = getClient();
  if (client?.connected) {
    client.sendStatus(status, message);
  }
}

/**
 * Create a typing guard that automatically manages typing indicators
 * for a conversation during message processing.
 *
 * Usage:
 * ```
 * const typing = createTypingGuard(conversationId);
 * typing.start();
 * // ... process message ...
 * typing.stop();
 * ```
 */
export function createTypingGuard(conversationId: string) {
  let typingInterval: ReturnType<typeof setInterval> | null = null;

  return {
    start(): void {
      startTyping(conversationId);
      // Re-send typing indicator every 3 seconds (common pattern)
      typingInterval = setInterval(() => {
        startTyping(conversationId);
      }, 3000);
    },
    stop(): void {
      if (typingInterval) {
        clearInterval(typingInterval);
        typingInterval = null;
      }
      stopTyping(conversationId);
    },
  };
}

/**
 * Agent status lifecycle manager.
 * Automatically updates status based on activity.
 */
export class AgentStatusManager {
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private idleTimeoutMs: number;

  constructor(idleTimeoutMs = 300_000) {
    // Default: 5 minutes idle = idle status
    this.idleTimeoutMs = idleTimeoutMs;
  }

  /**
   * Call when the agent processes a message.
   * Sets status to 'active' and resets the idle timer.
   */
  onActivity(): void {
    setAgentStatus('active');
    this.resetIdleTimer();
  }

  /**
   * Call when the agent explicitly goes busy (e.g., long-running task).
   */
  onBusy(message?: string): void {
    this.clearIdleTimer();
    setAgentStatus('busy', message);
  }

  /**
   * Call when shutting down.
   */
  onOffline(): void {
    this.clearIdleTimer();
    setAgentStatus('offline');
  }

  private resetIdleTimer(): void {
    this.clearIdleTimer();
    this.idleTimer = setTimeout(() => {
      setAgentStatus('idle');
    }, this.idleTimeoutMs);
  }

  private clearIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
  }
}