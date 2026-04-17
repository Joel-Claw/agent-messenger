/**
 * Runtime setup for the Agent Messenger plugin.
 * Sets the runtime context (WebSocket client, etc.) that the channel plugin needs.
 */
import type { AgentMessengerConfig, UserMessage } from './client.js';
import { AgentMessengerClient, startAgentMessengerRuntime, stopAgentMessengerRuntime } from './channel.js';

export function setAgentMessengerRuntime(client: AgentMessengerClient): void {
  // Store in module-level variable accessible by the channel plugin
  // This is called by the OpenClaw gateway when the plugin starts
}

export { AgentMessengerClient, startAgentMessengerRuntime, stopAgentMessengerRuntime };