/* Service Worker for Agent Messenger WebChat Push Notifications */

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { title: 'Agent Messenger', body: event.data ? event.data.text() : 'New message' };
  }

  const title = data.title || 'Agent Messenger';
  const options = {
    body: data.body || 'New message',
    icon: data.icon || '/logo192.png',
    badge: data.badge || '/logo192.png',
    tag: data.tag || 'am-message',
    data: {
      conversationId: data.conversation_id || '',
      url: data.url || '/',
    },
    vibrate: [100, 50, 100],
    actions: data.actions || [],
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const conversationId = event.notification.data?.conversationId;
  const url = conversationId ? `/?conversation=${conversationId}` : '/';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Focus existing window if available
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          client.navigate(url);
          return client.focus();
        }
      }
      // Open new window
      return self.clients.openWindow(url);
    })
  );
});

self.addEventListener('pushsubscriptionchange', (event) => {
  // Re-subscribe when subscription changes (e.g., VAPID key rotation)
  event.waitUntil(
    self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: self.registration.pushManager,
    }).then(() => {
      // The app will need to re-register with server on next visit
      console.log('[SW] Push subscription renewed');
    }).catch((err) => {
      console.error('[SW] Failed to renew push subscription:', err);
    })
  );
});