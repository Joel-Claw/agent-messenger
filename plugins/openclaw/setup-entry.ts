/**
 * Agent Messenger setup entry point for OpenClaw.
 * Lightweight loading during onboarding/setup flows.
 */
import { defineSetupPluginEntry } from 'openclaw/plugin-sdk/channel-core';
import { agentMessengerPlugin } from './src/channel.js';

export default defineSetupPluginEntry(agentMessengerPlugin);