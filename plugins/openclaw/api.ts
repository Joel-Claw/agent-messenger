/**
 * Public exports for the Agent Messenger plugin.
 */
export { agentMessengerPlugin, startAgentMessengerRuntime, stopAgentMessengerRuntime, AgentMessengerClient } from './src/channel.js';
export type { AgentMessengerConfig, UserMessage, ServerMessage } from './src/client.js';