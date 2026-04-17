/**
 * Agent Messenger plugin entry point for OpenClaw.
 */
import { defineChannelPluginEntry } from 'openclaw/plugin-sdk/channel-core';
import { agentMessengerPlugin } from './src/channel.js';
import { setRuntime, startRuntime, stopRuntime } from './src/runtime.js';
import type { ResolvedAccount } from './src/channel.js';

export default defineChannelPluginEntry({
  id: 'agent-messenger',
  name: 'Agent Messenger',
  description: 'Agent Messenger channel plugin for OpenClaw - connects to an Agent Messenger server for multi-agent chat',
  plugin: agentMessengerPlugin,
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
  registerFull(api) {
    // Register HTTP route for Agent Messenger status
    api.registerHttpRoute({
      path: '/agent-messenger/status',
      auth: 'operator',
      handler: async (_req, res) => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        const client = require('./src/runtime.js').getClient();
        res.end(JSON.stringify({
          status: client?.connected ? 'connected' : 'disconnected',
        }));
        return true;
      },
    });
  },
});