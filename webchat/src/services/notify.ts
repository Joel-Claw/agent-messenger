/**
 * Notification sound and browser notification utilities for Agent Messenger WebChat.
 */

let audioContext: AudioContext | null = null;

/**
 * Play a short notification beep using Web Audio API.
 * No external sound file required.
 */
export function playNotificationSound(): void {
  try {
    if (!audioContext) {
      audioContext = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
    }

    const ctx = audioContext;
    const now = ctx.currentTime;

    // Two-tone notification beep
    const osc1 = ctx.createOscillator();
    const gain1 = ctx.createGain();
    osc1.type = 'sine';
    osc1.frequency.setValueAtTime(880, now);
    gain1.gain.setValueAtTime(0.15, now);
    gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
    osc1.connect(gain1);
    gain1.connect(ctx.destination);
    osc1.start(now);
    osc1.stop(now + 0.15);

    const osc2 = ctx.createOscillator();
    const gain2 = ctx.createGain();
    osc2.type = 'sine';
    osc2.frequency.setValueAtTime(1100, now + 0.1);
    gain2.gain.setValueAtTime(0.12, now + 0.1);
    gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
    osc2.connect(gain2);
    gain2.connect(ctx.destination);
    osc2.start(now + 0.1);
    osc2.stop(now + 0.25);
  } catch {
    // Web Audio not available or blocked, silently ignore
  }
}

/**
 * Show a browser desktop notification (if permitted).
 * Falls back gracefully if Notification API not available or permission not granted.
 */
export function showDesktopNotification(title: string, body: string, conversationId?: string): void {
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted') {
    return;
  }

  try {
    const notification = new Notification(title, {
      body,
      icon: '/logo192.png',
      tag: conversationId ? `am-${conversationId}` : 'am-message',
    });

    notification.onclick = () => {
      window.focus();
      notification.close();
    };
  } catch {
    // Notification API not available
  }
}

/**
 * Request notification permission from the user.
 */
export async function requestNotificationPermission(): Promise<NotificationPermission> {
  if (typeof Notification === 'undefined') {
    return 'denied';
  }
  return Notification.requestPermission();
}

/**
 * Get current notification permission status.
 */
export function getNotificationPermission(): NotificationPermission {
  if (typeof Notification === 'undefined') {
    return 'denied';
  }
  return Notification.permission;
}