import { useCallback, useEffect, useRef, useState } from "preact/hooks";
import { TOKEN_CHANGED_EVENT, getToken, reportUnauthorized, wsProtocols } from "@/api/client";

export interface WsMessage {
  type: string;
  [key: string]: unknown;
}

/**
 * Close code the server uses when the socket offered no token or a wrong one.
 * Mirrors `WS_UNAUTHORIZED_CLOSE_CODE` in `pwnproxy/shared/api_token.py`.
 */
const WS_UNAUTHORIZED_CLOSE_CODE = 4401;

interface UseWebSocketOptions {
  url: string;
  onMessage?: (msg: WsMessage) => void;
  reconnectDelay?: number;
  maxReconnectDelay?: number;
}

/**
 * The only `new WebSocket` in the Web UI.
 *
 * The token rides in the `Sec-WebSocket-Protocol` header (`pwnproxy-token.<t>`),
 * never in the query string. Without a token it does not connect at all, and a
 * `4401` close means the token was rotated: it is dropped and the gate re-asks
 * for it instead of retrying forever. When a token is stored later, the socket
 * connects.
 */
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
    if (!getToken()) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(url, wsProtocols());
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

    ws.onclose = (event) => {
      setConnected(false);
      wsRef.current = null;
      if (event.code === WS_UNAUTHORIZED_CLOSE_CODE) {
        reportUnauthorized();
        return;
      }
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

  // A token pasted in the gate makes the waiting sockets connect.
  useEffect(() => {
    const handler = () => connect();
    window.addEventListener(TOKEN_CHANGED_EVENT, handler);
    return () => window.removeEventListener(TOKEN_CHANGED_EVENT, handler);
  }, [connect]);

  return { connected, lastMessage };
}
