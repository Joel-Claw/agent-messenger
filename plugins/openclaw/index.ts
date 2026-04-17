/**
 * Agent Messenger plugin entry point for OpenClaw.
 */
import { defineChannelPluginEntry } from 'openclaw/plugin-sdk/channel-core';
import { agentMessengerPlugin } from './src/channel.js';

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
        // Return connection status
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ status: 'ok' }));
        return true;
      },
    });
  },
});