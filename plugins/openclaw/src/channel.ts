/**
 * Agent Messenger channel plugin for OpenClaw.
 *
 * This plugin connects OpenClaw to an Agent Messenger server, allowing
 * users to chat with the AI agent through the Agent Messenger web/mobile clients.
 *
 * The plugin:
 * - Registers as an OpenClaw channel
 * - Connects to the Agent Messenger server via WebSocket
 * - Forwards incoming user messages to OpenClaw's message pipeline
 * - Sends OpenClaw responses back through the Agent Messenger server
 */
import {
  createChatChannelPlugin,
  createChannelPluginBase,
} from 'openclaw/plugin-sdk/channel-core';
import type { OpenClawConfig } from 'openclaw/plugin-sdk/channel-core';
import { getClient } from './runtime.js';

type ResolvedAccount = {
  accountId: string | null;
  serverUrl: string;
  apiKey: string;
  agentId: string;
  agentName: string;
  agentModel: string;
  agentPersonality: string;
  agentSpecialty: string;
  allowFrom: string[];
  dmPolicy: string | undefined;
};

function resolveAccount(
  cfg: OpenClawConfig,
  accountId?: string | null,
): ResolvedAccount {
  const section = (cfg.channels as Record<string, any>)?.['agent-messenger'];
  const serverUrl = section?.serverUrl;
  const apiKey = section?.apiKey;
  const agentId = section?.agentId;

  if (!serverUrl) throw new Error('agent-messenger: serverUrl is required');
  if (!apiKey) throw new Error('agent-messenger: apiKey is required');
  if (!agentId) throw new Error('agent-messenger: agentId is required');

  return {
    accountId: accountId ?? null,
    serverUrl,
    apiKey,
    agentId,
    agentName: section?.agentName || 'OpenClaw Agent',
    agentModel: section?.agentModel || '',
    agentPersonality: section?.agentPersonality || '',
    agentSpecialty: section?.agentSpecialty || '',
    allowFrom: section?.allowFrom ?? [],
    dmPolicy: section?.dmSecurity,
  };
}

export const agentMessengerPlugin = createChatChannelPlugin<ResolvedAccount>({
  base: createChannelPluginBase({
    id: 'agent-messenger',
    setup: {
      resolveAccount,
      inspectAccount(cfg, accountId) {
        const section =
          (cfg.channels as Record<string, any>)?.['agent-messenger'];
        return {
          enabled: Boolean(section?.serverUrl && section?.apiKey && section?.agentId),
          configured: Boolean(section?.serverUrl && section?.apiKey && section?.agentId),
          serverUrl: section?.serverUrl ? 'configured' : 'missing',
        };
      },
    },
  }),

  // DM security: who can message the bot
  security: {
    dm: {
      channelKey: 'agent-messenger',
      resolvePolicy: (account) => account.dmPolicy,
      resolveAllowFrom: (account) => account.allowFrom,
      defaultPolicy: 'allowlist',
    },
  },

  // Threading: replies go back to the same conversation
  threading: { topLevelReplyToMode: 'reply' },

  // Outbound: send messages back to users through Agent Messenger
  outbound: {
    attachedResults: {
      sendText: async (params) => {
        const client = getClient();
        if (!client) {
          throw new Error('Agent Messenger client not connected');
        }

        // params.to contains the conversation_id / target
        const conversationId = params.to;
        client.sendMessage(params.text, conversationId);

        return { messageId: `am-${Date.now()}` };
      },
    },
    base: {
      sendMedia: async (params) => {
        const client = getClient();
        if (!client) {
          throw new Error('Agent Messenger client not connected');
        }

        // Agent Messenger currently only supports text messages
        // Media can be sent as a URL in the text content
        const conversationId = params.to;
        client.sendMessage(`[Media: ${params.filePath}]`, conversationId);
      },
    },
  },
});

export { ResolvedAccount };