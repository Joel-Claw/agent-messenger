/**
 * Mock for openclaw/plugin-sdk/inbound-reply-dispatch
 */
export async function dispatchInboundDirectDmWithRuntime(params: any): Promise<void> {
  // No-op in mock
}

export function resolveInboundDirectDmAccessWithRuntime(params: any): any {
  return { allowed: true };
}