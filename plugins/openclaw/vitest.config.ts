import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    alias: {
      'openclaw/plugin-sdk/channel-core': resolve(__dirname, 'src/__mocks__/openclaw-channel-core.ts'),
      'openclaw/plugin-sdk/runtime': resolve(__dirname, 'src/__mocks__/openclaw-runtime.ts'),
      'openclaw/plugin-sdk/reply-payload': resolve(__dirname, 'src/__mocks__/openclaw-reply-payload.ts'),
      'openclaw/plugin-sdk/inbound-reply-dispatch': resolve(__dirname, 'src/__mocks__/openclaw-inbound-reply-dispatch.ts'),
    },
  },
  test: {
    globals: false,
    include: ['src/**/*.test.ts'],
    testTimeout: 15000,
  },
});