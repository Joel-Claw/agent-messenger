import { useEffect, useRef, useCallback, useState } from 'react';
import { WS_BASE } from '../services/api';
import type { ServerMessage } from '../types';

interface UseWebSocketOptions {
  token: string | null;
  onMessage?: (msg: ServerMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  reconnectAttempts?: number;
  reconnectInterval?: number;
}

interface UseWebSocketReturn {
  connected: boolean;
  send: (msg: object) => void;
  ws: WebSocket | null;
}

export function useWebSocket({
  token,
  onMessage,
  onConnect,
  onDisconnect,
  reconnectAttempts = 10,
  reconnectInterval = 3000,
}: UseWebSocketOptions): UseWebSocketReturn {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const attemptsRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onMessageRef = useRef(onMessage);
  const onConnectRef = useRef(onConnect);
  const onDisconnectRef = useRef(onDisconnect);

  onMessageRef.current = onMessage;
  onConnectRef.current = onConnect;
  onDisconnectRef.current = onDisconnect;

  const connect = useCallback(() => {
    if (!token) return;

    const url = `${WS_BASE}/client/connect?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(url);

    ws.onopen = () => {
      setConnected(true);
      attemptsRef.current = 0;
      onConnectRef.current?.();
    };

    ws.onmessage = (event) => {
      try {
        const msg: ServerMessage = JSON.parse(event.data);
        onMessageRef.current?.(msg);
      } catch {
        console.error('[WebChat] Failed to parse message');
      }
    };

    ws.onclose = () => {
      setConnected(false);
      onDisconnectRef.current?.();

      // Reconnect
      if (attemptsRef.current < reconnectAttempts) {
        attemptsRef.current++;
        const delay = Math.min(reconnectInterval * Math.pow(1.5, attemptsRef.current), 30000);
        reconnectTimerRef.current = setTimeout(() => {
          connect();
        }, delay);
      }
    };

    ws.onerror = (err) => {
      console.error('[WebChat] WebSocket error:', err);
    };

    wsRef.current = ws;
  }, [token, reconnectAttempts, reconnectInterval]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        attemptsRef.current = reconnectAttempts; // Prevent reconnect
        wsRef.current.close();
      }
    };
  }, [connect, reconnectAttempts]);

  const send = useCallback((msg: object) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  return { connected, send, ws: wsRef.current };
}