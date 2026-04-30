import React, { useState, useEffect, useCallback } from 'react';
import { API_BASE } from '../services/api';

interface PushSubscriptionProps {
  token: string;
}

export function PushSubscription({ token }: PushSubscriptionProps) {
  const [supported, setSupported] = useState(false);
  const [subscribed, setSubscribed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [permission, setPermission] = useState<NotificationPermission>('default');

  useEffect(() => {
    // Check if push is supported
    const isSupported = 'serviceWorker' in navigator && 'PushManager' in window;
    setSupported(isSupported);

    if (isSupported) {
      setPermission(Notification.permission);

      // Check existing subscription
      navigator.serviceWorker.ready.then(reg => {
        return reg.pushManager.getSubscription();
      }).then(sub => {
        setSubscribed(!!sub);
      }).catch(() => {});
    }

    // Listen for push subscription change events from service worker
    const handleSWMessage = (event: MessageEvent) => {
      if (event.data?.type === 'push-subscription-change') {
        // The subscription changed, try to re-subscribe
        setSubscribed(false);
        // Auto-re-subscribe after a short delay
        setTimeout(() => subscribe(), 1000);
      }
    };

    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.addEventListener('message', handleSWMessage);
    }

    return () => {
      if ('serviceWorker' in navigator) {
        navigator.serviceWorker.removeEventListener('message', handleSWMessage);
      }
    };
  }, [subscribe]);

  const subscribe = useCallback(async () => {
    if (!supported) return;
    setLoading(true);
    setError(null);

    try {
      // Request notification permission
      const perm = await Notification.requestPermission();
      setPermission(perm);
      if (perm !== 'granted') {
        setError('Notification permission denied');
        setLoading(false);
        return;
      }

      // Register service worker
      const reg = await navigator.serviceWorker.ready;

      // Get VAPID public key from server
      const vapidRes = await fetch(`${API_BASE}/push/vapid-key`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!vapidRes.ok) {
        setError('Push notifications not configured on server');
        setLoading(false);
        return;
      }
      const { public_key } = await vapidRes.json();

      // Subscribe to push
      const subscription = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(public_key),
      });

      // Send subscription to server
      const subJson = subscription.toJSON();
      const registerRes = await fetch(`${API_BASE}/push/web-subscribe`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          endpoint: subJson.endpoint,
          keys: subJson.keys,
        }),
      });

      if (!registerRes.ok) {
        setError('Failed to register push subscription');
        // Unsubscribe locally since server rejected
        await subscription.unsubscribe();
        setLoading(false);
        return;
      }

      setSubscribed(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to subscribe');
    } finally {
      setLoading(false);
    }
  }, [supported, token]);

  const unsubscribe = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const reg = await navigator.serviceWorker.ready;
      const sub = await reg.pushManager.getSubscription();
      if (sub) {
        await sub.unsubscribe();

        // Tell server to remove subscription
        await fetch(`${API_BASE}/push/web-unsubscribe`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ endpoint: sub.endpoint }),
        });
      }
      setSubscribed(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unsubscribe');
    } finally {
      setLoading(false);
    }
  }, [token]);

  if (!supported) {
    return (
      <div style={styles.container}>
        <div style={styles.unsupported}>Push notifications not supported in this browser</div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.row}>
        <div style={styles.info}>
          <span style={styles.icon}>{subscribed ? '🔔' : '🔕'}</span>
          <span style={styles.label}>
            {subscribed ? 'Push notifications enabled' : 'Push notifications'}
          </span>
        </div>
        {!subscribed ? (
          <button
            onClick={subscribe}
            disabled={loading || permission === 'denied'}
            style={{
              ...styles.button,
              ...styles.enableButton,
              opacity: loading || permission === 'denied' ? 0.5 : 1,
            }}
          >
            {loading ? '⏳' : 'Enable'}
          </button>
        ) : (
          <button
            onClick={unsubscribe}
            disabled={loading}
            style={{
              ...styles.button,
              ...styles.disableButton,
              opacity: loading ? 0.5 : 1,
            }}
          >
            {loading ? '⏳' : 'Disable'}
          </button>
        )}
      </div>
      {permission === 'denied' && (
        <div style={styles.permissionNote}>
          Notifications blocked. Allow in browser settings to enable push.
        </div>
      )}
      {error && <div style={styles.error}>{error}</div>}
    </div>
  );
}

function urlBase64ToUint8Array(base64: string): Uint8Array {
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const b64 = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(b64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i++) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.375rem',
  },
  unsupported: {
    fontSize: '0.75rem',
    color: '#6e7681',
  },
  row: {
    display: 'flex',
    justifyContent: 'space-between' as const,
    alignItems: 'center' as const,
    gap: '0.75rem',
  },
  info: {
    display: 'flex',
    alignItems: 'center' as const,
    gap: '0.5rem',
  },
  icon: {
    fontSize: '1rem',
  },
  label: {
    fontSize: '0.8rem',
    color: '#e6edf3',
  },
  button: {
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '0.75rem',
    fontWeight: 500,
    padding: '0.25rem 0.75rem',
  },
  enableButton: {
    backgroundColor: '#238636',
    color: '#ffffff',
  },
  disableButton: {
    backgroundColor: '#21262d',
    color: '#8b949e',
    border: '1px solid #30363d',
  },
  permissionNote: {
    fontSize: '0.7rem',
    color: '#f85149',
  },
  error: {
    fontSize: '0.7rem',
    color: '#f85149',
  },
};