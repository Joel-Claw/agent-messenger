/**
 * Tests for Agent Messenger typing and status indicators (Task 11).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock runtime
const mockSendTyping = vi.fn();
const mockSendStatus = vi.fn();

vi.mock('../runtime.js', () => ({
  getClient: () => ({
    connected: true,
    sendTyping: mockSendTyping,
    sendStatus: mockSendStatus,
  }),
}));

import {
  startTyping,
  stopTyping,
  setAgentStatus,
  createTypingGuard,
  AgentStatusManager,
} from '../typing.js';

describe('Typing Indicators', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should send typing start', () => {
    startTyping('conv-1');
    expect(mockSendTyping).toHaveBeenCalledWith('conv-1', true);
  });

  it('should send typing stop', () => {
    stopTyping('conv-1');
    expect(mockSendTyping).toHaveBeenCalledWith('conv-1', false);
  });

  it('should handle typing guard lifecycle', () => {
    const guard = createTypingGuard('conv-1');

    guard.start();
    expect(mockSendTyping).toHaveBeenCalledWith('conv-1', true);

    // Advance 3 seconds - should re-send typing
    vi.advanceTimersByTime(3000);
    expect(mockSendTyping).toHaveBeenCalledTimes(2);

    guard.stop();
    expect(mockSendTyping).toHaveBeenCalledWith('conv-1', false);
  });

  it('should clear interval on stop', () => {
    const guard = createTypingGuard('conv-1');
    guard.start();
    guard.stop();

    vi.advanceTimersByTime(10000);
    // Should not send more typing after stop
    expect(mockSendTyping).toHaveBeenCalledTimes(2); // start + stop
  });
});

describe('Agent Status', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should send status update', () => {
    setAgentStatus('active');
    expect(mockSendStatus).toHaveBeenCalledWith('active', undefined);
  });

  it('should send status with message', () => {
    setAgentStatus('busy', 'Processing long task');
    expect(mockSendStatus).toHaveBeenCalledWith('busy', 'Processing long task');
  });

  it('should manage idle timeout', () => {
    const manager = new AgentStatusManager(5000);

    manager.onActivity();
    expect(mockSendStatus).toHaveBeenCalledWith('active');

    vi.advanceTimersByTime(5000);
    expect(mockSendStatus).toHaveBeenCalledWith('idle');
  });

  it('should reset idle timer on activity', () => {
    const manager = new AgentStatusManager(5000);

    manager.onActivity();
    vi.advanceTimersByTime(3000);

    manager.onActivity();
    vi.advanceTimersByTime(3000);

    // Should not have gone idle yet (reset at 3s)
    expect(mockSendStatus).not.toHaveBeenCalledWith('idle');

    vi.advanceTimersByTime(2000);
    // Now should be idle
    expect(mockSendStatus).toHaveBeenCalledWith('idle');
  });

  it('should clear idle timer on busy', () => {
    const manager = new AgentStatusManager(5000);

    manager.onActivity();
    manager.onBusy('Working');

    vi.advanceTimersByTime(10000);
    // Should NOT go idle while busy
    expect(mockSendStatus).not.toHaveBeenCalledWith('idle');
  });

  it('should set offline and clear timers', () => {
    const manager = new AgentStatusManager(5000);

    manager.onActivity();
    manager.onOffline();

    expect(mockSendStatus).toHaveBeenCalledWith('offline');
  });
});