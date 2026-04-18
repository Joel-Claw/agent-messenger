/**
 * Mock for openclaw/plugin-sdk/channel-core
 *
 * The real createChatChannelPlugin flattens the base properties onto
 * the returned plugin object. This mock replicates that behavior.
 */

export function createChannelPluginBase(opts: any): any {
  return opts;
}

export function createChatChannelPlugin(opts: any): any {
  // Flatten: merge base properties onto the plugin object
  const { base, ...rest } = opts;
  if (base) {
    return { ...base, ...rest };
  }
  return rest;
}

export function defineChannelPluginEntry(opts: any): any {
  return opts;
}