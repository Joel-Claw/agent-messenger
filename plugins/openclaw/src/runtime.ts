/**
 * Agent Messenger runtime module.
 *
 * Bridges the WebSocket client to OpenClaw's inbound message pipeline.
 * Receives PluginRuntime from OpenClaw on startup, connects to the
 * Agent Messenger server, and dispatches incoming user messages through
 * the standard Direct DM pipeline.
 */
import type { PluginRuntime } from 'openclaw/plugin-sdk/runtime';
import type { OutboundReplyPayload } from 'openclaw/plugin-sdk/reply-payload';
import {
  dispatchInboundDirectDmWithRuntime,
  resolveInboundDirectDmAccessWithRuntime,
} from 'openclaw/plugin-sdk/inbound-reply-dispatch';
import { AgentMessengerClient, type UserMessage } from './client.js';
import type { ResolvedAccount } from './channel.js';

const CHANNEL_ID = 'agent-messenger';
const CHANNEL_LABEL = 'Agent Messenger';

let runtime: PluginRuntime | null = null;
let client: AgentMessengerClient | null = null;
let currentAccount: ResolvedAccount | null = null;

/**
 * Set the PluginRuntime reference. Called by OpenClaw when the plugin is loaded.
 */
export function setRuntime(rt: PluginRuntime): void {
  runtime = rt;
}

/**
 * Get the current PluginRuntime (for use by outbound adapter).
 */
export function getRuntime(): PluginRuntime | null {
  return runtime;
}

/**
 * Start the Agent Messenger runtime: connect to server and begin
 * dispatching inbound messages.
 */
export async function startRuntime(account: ResolvedAccount): Promise<void> {
  if (!runtime) {
    throw new Error('Agent Messenger: PluginRuntime not set. Cannot start.');
  }

  currentAccount = account;

  client = new AgentMessengerClient({
    serverUrl: account.serverUrl,
    apiKey: account.apiKey,
    agentId: account.agentId,
    agentName: account.agentName,
    agentModel: account.agentModel,
    agentPersonality: account.agentPersonality,
    agentSpecialty: account.agentSpecialty,
  });

  // Wire inbound user messages to OpenClaw's pipeline
  client.onMessage((msg: UserMessage) => {
    handleInboundUserMessage(msg).catch((err) => {
      console.error('[AgentMessenger] Failed to handle inbound message:', err);
    });
  });

  // Wire conversation creation events
  client.onConversation((msg) => {
    console.log(
      `[AgentMessenger] New conversation created: ${msg.conversation_id} with user ${msg.user_id}`
    );
  });

  await client.connect();
  console.log('[AgentMessenger] Runtime started, connected to server');
}

/**
 * Stop the runtime and disconnect from the server.
 */
export function stopRuntime(): void {
  if (client) {
    client.disconnect();
    client = null;
  }
  currentAccount = null;
}

/**
 * Get the active client (for outbound adapter).
 */
export function getClient(): AgentMessengerClient | null {
  return client;
}

/**
 * Handle an inbound user message by dispatching it through OpenClaw's
 * Direct DM pipeline.
 */
async function handleInboundUserMessage(msg: UserMessage): Promise<void> {
  if (!runtime || !currentAccount) {
    console.error('[AgentMessenger] Cannot dispatch: runtime or account not set');
    return;
  }

  const cfg = {} as any; // Will be provided by runtime context

  // Build the DirectDmRuntime from PluginRuntime.channel
  const dmRuntime = {
    channel: {
      routing: {
        resolveAgentRoute: runtime.channel.routing.resolveAgentRoute,
      },
      session: {
        resolveStorePath: runtime.channel.session.resolveStorePath,
        readSessionUpdatedAt: runtime.channel.session.readSessionUpdatedAt,
        recordInboundSession: runtime.channel.session.recordInboundSession,
      },
      reply: {
        resolveEnvelopeFormatOptions: runtime.channel.reply.resolveEnvelopeFormatOptions,
        formatAgentEnvelope: runtime.channel.reply.formatAgentEnvelope,
        finalizeInboundContext: runtime.channel.reply.finalizeInboundContext,
        dispatchReplyWithBufferedBlockDispatcher:
          runtime.channel.reply.dispatchReplyWithBufferedBlockDispatcher,
      },
    },
  };

  // Deliver outbound replies back through the Agent Messenger server
  const deliver = async (payload: OutboundReplyPayload): Promise<void> => {
    if (!client || !client.connected) {
      console.error('[AgentMessenger] Cannot deliver reply: not connected');
      return;
    }

    // Send each text chunk as a separate message
    if (payload.text) {
      client.sendMessage(payload.text, msg.conversation_id);
    }
  };

  try {
    await dispatchInboundDirectDmWithRuntime({
      cfg,
      runtime: dmRuntime,
      channel: CHANNEL_ID,
      channelLabel: CHANNEL_LABEL,
      accountId: currentAccount.accountId ?? 'default',
      peer: {
        senderId: msg.user_id,
        address: msg.user_id,
      },
      senderId: msg.user_id,
      senderAddress: msg.user_id,
      recipientAddress: currentAccount.agentId,
      conversationLabel: `Agent Messenger:${msg.conversation_id}`,
      rawBody: msg.content,
      messageId: `${msg.conversation_id}:${msg.timestamp}`,
      timestamp: new Date(msg.timestamp).getTime() / 1000,
      deliver,
      onRecordError: (err) => {
        console.error('[AgentMessenger] Error recording inbound session:', err);
      },
      onDispatchError: (err, info) => {
        console.error(`[AgentMessenger] Error dispatching reply (${info.kind}):`, err);
      },
    });
  } catch (err) {
    console.error('[AgentMessenger] Failed to dispatch inbound DM:', err);
  }
}