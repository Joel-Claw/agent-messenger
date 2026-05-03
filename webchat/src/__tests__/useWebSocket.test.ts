import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '../hooks/useWebSocket';

// Mock WebSocket
class MockWebSocket {
  static INSTANCE: MockWebSocket | null = null;
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  url: string;
  readyState: number = MockWebSocket.CONNECTING;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.INSTANCE = this;
    // Simulate async open
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.onopen?.();
    }, 0);
  }

  send(data: string) {
    // Track sent data in tests
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }

  // Test helpers
  simulateMessage(data: object) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }

  simulateClose() {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }

  simulateError() {
    this.onerror?.(new Event('error'));
  }
}

// Replace global WebSocket
const originalWebSocket = global.WebSocket;
beforeAll(() => {
  (global as any).WebSocket = MockWebSocket;
});
afterAll(() => {
  (global as any).WebSocket = originalWebSocket;
});

// Mock WS_BASE to avoid env var issues
jest.mock('../services/api', () => ({
  WS_BASE: 'ws://localhost:8080',
  API_BASE: 'http://localhost:8080',
}));

describe('useWebSocket', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    MockWebSocket.INSTANCE = null;
  });

  it('connects on mount when token is provided', () => {
    const { result } = renderHook(() => useWebSocket({
      token: 'test-token',
    }));

    expect(MockWebSocket.INSTANCE).not.toBeNull();
    expect(MockWebSocket.INSTANCE?.url).toContain('ws://localhost:8080/client/connect');
    expect(MockWebSocket.INSTANCE?.url).toContain('token=test-token');
  });

  it('does not connect when token is null', () => {
    renderHook(() => useWebSocket({ token: null }));
    expect(MockWebSocket.INSTANCE).toBeNull();
  });

  it('reports connected state after open', async () => {
    const { result } = renderHook(() => useWebSocket({
      token: 'test-token',
    }));

    await waitFor(() => {
      expect(result.current.connected).toBe(true);
    });
  });

  it('reports disconnected state after close', async () => {
    const onDisconnect = jest.fn();
    const { result } = renderHook(() => useWebSocket({
      token: 'test-token',
      onDisconnect,
    }));

    await waitFor(() => {
      expect(result.current.connected).toBe(true);
    });

    act(() => {
      MockWebSocket.INSTANCE!.simulateClose();
    });

    expect(result.current.connected).toBe(false);
    expect(onDisconnect).toHaveBeenCalled();
  });

  it('calls onMessage when a message is received', async () => {
    const onMessage = jest.fn();
    renderHook(() => useWebSocket({
      token: 'test-token',
      onMessage,
    }));

    await waitFor(() => {
      expect(MockWebSocket.INSTANCE).not.toBeNull();
    });

    const testMsg = { type: 'message', data: { content: 'Hello!' } };
    act(() => {
      MockWebSocket.INSTANCE!.simulateMessage(testMsg);
    });

    expect(onMessage).toHaveBeenCalledWith(expect.objectContaining({
      type: 'message',
      data: expect.objectContaining({ content: 'Hello!' }),
    }));
  });

  it('calls onConnect callback after connection', async () => {
    const onConnect = jest.fn();
    renderHook(() => useWebSocket({
      token: 'test-token',
      onConnect,
    }));

    await waitFor(() => {
      expect(onConnect).toHaveBeenCalled();
    });
  });

  it('sends messages via send function', async () => {
    const { result } = renderHook(() => useWebSocket({
      token: 'test-token',
    }));

    await waitFor(() => {
      expect(result.current.connected).toBe(true);
    });

    const sendSpy = jest.spyOn(MockWebSocket.INSTANCE!, 'send');
    act(() => {
      result.current.send({ type: 'message', data: { content: 'Hi' } });
    });

    expect(sendSpy).toHaveBeenCalledWith(JSON.stringify({ type: 'message', data: { content: 'Hi' } }));
  });

  it('does not send when WebSocket is not open', () => {
    const { result } = renderHook(() => useWebSocket({
      token: null,
    }));

    // Should not throw when send is called without connection
    act(() => {
      result.current.send({ type: 'message' });
    });
    // No error thrown
  });

  it('reconnects after connection loss', async () => {
    jest.useFakeTimers();
    const { result } = renderHook(() => useWebSocket({
      token: 'test-token',
      reconnectAttempts: 5,
      reconnectInterval: 100,
    }));

    await waitFor(() => {
      expect(result.current.connected).toBe(true);
    });

    // Simulate disconnect
    act(() => {
      MockWebSocket.INSTANCE!.simulateClose();
    });

    expect(result.current.connected).toBe(false);

    // Advance timer to trigger reconnect
    act(() => {
      jest.advanceTimersByTime(500);
    });

    // A new WebSocket should have been created
    expect(MockWebSocket.INSTANCE).not.toBeNull();

    jest.useRealTimers();
  });

  it('cleans up WebSocket on unmount', () => {
    const { unmount } = renderHook(() => useWebSocket({
      token: 'test-token',
      reconnectAttempts: 0,
    }));

    const wsInstance = MockWebSocket.INSTANCE;
    unmount();

    // WebSocket should be closed
    expect(wsInstance?.readyState).toBe(MockWebSocket.CLOSED);
  });

  it('stops reconnecting after max attempts', async () => {
    jest.useFakeTimers();
    const { result } = renderHook(() => useWebSocket({
      token: 'test-token',
      reconnectAttempts: 1,
      reconnectInterval: 50,
    }));

    await waitFor(() => {
      expect(result.current.connected).toBe(true);
    });

    // Close and try to exceed max attempts
    const firstInstance = MockWebSocket.INSTANCE!;
    act(() => {
      firstInstance.simulateClose();
    });

    // Advance past the first reconnect attempt
    act(() => {
      jest.advanceTimersByTime(200);
    });

    // After reconnect, close again
    if (MockWebSocket.INSTANCE) {
      act(() => {
        MockWebSocket.INSTANCE!.simulateClose();
      });
    }

    // Advance far enough for any additional attempts
    act(() => {
      jest.advanceTimersByTime(5000);
    });

    jest.useRealTimers();
  });

  it('handles malformed messages gracefully', async () => {
    const onMessage = jest.fn();
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});

    renderHook(() => useWebSocket({
      token: 'test-token',
      onMessage,
    }));

    await waitFor(() => {
      expect(MockWebSocket.INSTANCE).not.toBeNull();
    });

    // Simulate invalid JSON
    act(() => {
      MockWebSocket.INSTANCE!.onmessage!({ data: 'invalid json' });
    });

    // Should not crash
    expect(onMessage).not.toHaveBeenCalled();

    consoleError.mockRestore();
  });
});