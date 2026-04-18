/**
 * Public exports for the Agent Messenger plugin.
 */
export { agentMessengerPlugin } from './src/channel.js';
export type { ResolvedAccount } from './src/channel.js';
export { AgentMessengerClient } from './src/client.js';
export type { AgentMessengerConfig, UserMessage, ServerMessage } from './src/client.js';
export { setRuntime, startRuntime, stopRuntime, resetRuntime, getClient } from './src/runtime.js';
export { createTypingGuard, AgentStatusManager, startTyping, stopTyping, setAgentStatus } from './src/typing.js';