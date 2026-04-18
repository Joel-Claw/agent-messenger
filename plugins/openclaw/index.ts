/**
 * Agent Messenger plugin entry point for OpenClaw.
 *
 * Handles:
 * - Plugin registration (CLI metadata, HTTP routes)
 * - Lifecycle management (auto-connect on startup, disconnect on shutdown)
 * - Runtime wiring (PluginRuntime → WebSocket client → OpenClaw pipeline)
 */
import { defineChannelPluginEntry } from 'openclaw/plugin-sdk/channel-core';
import { agentMessengerPlugin } from './src/channel.js';
import { setRuntime, startRuntime, stopRuntime, getClient } from './src/runtime.js';
import type { ResolvedAccount } from './src/channel.js';

export default defineChannelPluginEntry({
  id: 'agent-messenger',
  name: 'Agent Messenger',
  description: 'Agent Messenger channel plugin for OpenClaw - connects to an Agent Messenger server for multi-agent chat',
  plugin: agentMessengerPlugin,

  /**
   * Register CLI commands for agent-messenger management.
   */
  registerCliMetadata(api) {
    api.registerCli(
      ({ program }) => {
        program
          .command('agent-messenger')
          .description('Agent Messenger channel management');
      },
      {
        descriptors: [
          {
            name: 'agent-messenger',
            description: 'Agent Messenger channel management',
            hasSubcommands: false,
          },
        ],
      },
    );
  },

  /**
   * Register full plugin: HTTP routes and lifecycle hooks.
   *
   * This is called by OpenClaw when the gateway starts. It:
   * 1. Sets the PluginRuntime on the runtime module
   * 2. Resolves the account from config
   * 3. Starts the WebSocket connection to the Agent Messenger server
   * 4. Registers HTTP routes for status monitoring
   * 5. Registers shutdown hook for clean disconnect
   */
  registerFull(api) {
    // --- Lifecycle: auto-connect on startup ---

    // Set the PluginRuntime so the runtime module can access it
    const runtime = api.getRuntime?.() ?? null;
    if (runtime) {
      setRuntime(runtime);
    }

    // Resolve account from config and start the connection
    const cfg = api.getConfig?.() ?? {};
    try {
      const account = agentMessengerPlugin.setup!.resolveAccount(cfg, undefined) as ResolvedAccount;

      // Auto-connect: start the WebSocket client and begin dispatching
      // inbound messages through OpenClaw's pipeline
      startRuntime(account)
        .then(() => {
          console.log('[AgentMessenger] Auto-connected on startup');
        })
        .catch((err: Error) => {
          console.error('[AgentMessenger] Auto-connect failed on startup:', err.message);
          console.error('[AgentMessenger] Plugin will retry on next reconnect cycle');
        });
    } catch (err) {
      // Config may not be available yet (e.g. during first setup)
      console.warn('[AgentMessenger] Could not resolve account on startup:', (err as Error).message);
    }

    // --- HTTP route: status endpoint ---
    api.registerHttpRoute({
      path: '/agent-messenger/status',
      auth: 'operator',
      handler: async (_req, res) => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        const client = getClient();
        res.end(JSON.stringify({
          status: client?.connected ? 'connected' : 'disconnected',
          agentId: client ? 'connected' : 'not_connected',
        }));
        return true;
      },
    });

    // --- Lifecycle: disconnect on shutdown ---
    api.registerShutdownHook?.(() => {
      console.log('[AgentMessenger] Shutting down, disconnecting from server');
      stopRuntime();
    });
  },
});