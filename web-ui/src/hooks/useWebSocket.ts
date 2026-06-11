import { useCallback, useEffect, useRef, useState } from "preact/hooks";

export interface WsMessage {
  type: string;
  [key: string]: unknown;
}

interface UseWebSocketOptions {
  url: string;
  onMessage?: (msg: WsMessage) => void;
  reconnectDelay?: number;
  maxReconnectDelay?: number;
}

export function useWebSocket({
  url,
  onMessage,
  reconnectDelay = 1000,
  maxReconnectDelay = 30000,
}: UseWebSocketOptions) {
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<number>(reconnectDelay);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      retryRef.current = reconnectDelay;
    };

    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        setLastMessage(msg);
        onMessageRef.current?.(msg);
      } catch {
        // ignore malformed messages
      }
    };

    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
      timerRef.current = setTimeout(() => {
        retryRef.current = Math.min(retryRef.current * 1.5, maxReconnectDelay);
        connect();
      }, retryRef.current);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [url, reconnectDelay, maxReconnectDelay]);

  const disconnect = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    wsRef.current?.close();
    wsRef.current = null;
    setConnected(false);
  }, []);

  useEffect(() => {
    connect();
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return { connected, lastMessage };
}
