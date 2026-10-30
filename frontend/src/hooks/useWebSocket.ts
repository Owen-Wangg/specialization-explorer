import { useEffect, useRef, useCallback, useState } from "react";

interface WebSocketMessage {
  type: "start" | "chunk" | "complete" | "error" | "pong";
  content?: string;
  message?: string;
  sources?: string[];
}

// Lambda does not guarantee how long an idle execution environment survives; 5 minutes is a
// common keep-warm interval and stays under API Gateway's 10 minute WebSocket idle timeout
const WARMUP_INTERVAL_MS = 5 * 60 * 1000;

interface UseWebSocketOptions {
  onMessage?: (message: WebSocketMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
}

export const useWebSocket = (
  url: string | null,
  options: UseWebSocketOptions = {}
) => {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const heartbeatIntervalRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const isManualDisconnectRef = useRef(false);
  const [connectionState, setConnectionState] = useState<
    "connecting" | "connected" | "disconnected" | "error"
  >("disconnected");

  // Store callbacks in refs to avoid dependency issues
  const callbacksRef = useRef(options);
  callbacksRef.current = options;

  // Asks the server to warm the text generation Lambda so the next message skips its cold start.
  // The same message keeps the connection inside API Gateway's 10 minute idle timeout.
  const sendWarmup = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      try {
        wsRef.current.send(JSON.stringify({ action: "warmup" }));
      } catch (error) {
        console.error("[WebSocket] Error sending warm-up:", error);
      }
    }
  }, []);

  const stopHeartbeat = useCallback(() => {
    if (heartbeatIntervalRef.current) {
      window.clearInterval(heartbeatIntervalRef.current);
      heartbeatIntervalRef.current = null;
    }
  }, []);

  // Warm immediately, then repeat only while the tab is visible
  const startHeartbeat = useCallback(() => {
    stopHeartbeat();
    if (document.visibilityState !== "visible") {
      return;
    }
    sendWarmup();
    heartbeatIntervalRef.current = window.setInterval(
      sendWarmup,
      WARMUP_INTERVAL_MS
    );
  }, [sendWarmup, stopHeartbeat]);

  const scheduleReconnect = useCallback(() => {
    if (isManualDisconnectRef.current) {
      console.log("[WebSocket] Manual disconnect, not reconnecting");
      return;
    }

    if (reconnectAttemptsRef.current >= 10) {
      console.log("[WebSocket] Max reconnection attempts reached");
      setConnectionState("error");
      return;
    }

    if (reconnectTimeoutRef.current) {
      window.clearTimeout(reconnectTimeoutRef.current);
    }

    const delay = Math.min(
      1000 * Math.pow(2, reconnectAttemptsRef.current),
      30000
    );
    console.log(
      `[WebSocket] Scheduling reconnect attempt ${
        reconnectAttemptsRef.current + 1
      }/10 in ${delay}ms`
    );

    reconnectTimeoutRef.current = window.setTimeout(() => {
      reconnectAttemptsRef.current++;
      connect();
    }, delay);
  }, []);

  const connect = useCallback(() => {
    if (
      !url ||
      wsRef.current?.readyState === WebSocket.CONNECTING ||
      wsRef.current?.readyState === WebSocket.OPEN
    ) {
      return;
    }

    setConnectionState("connecting");

    try {
      wsRef.current = new WebSocket(url);

      wsRef.current.onopen = () => {
        console.log("[WebSocket] Connected successfully");
        setConnectionState("connected");
        reconnectAttemptsRef.current = 0;
        startHeartbeat();
        callbacksRef.current.onConnect?.();
      };

      wsRef.current.onmessage = (event) => {
        try {
          if (typeof event.data === "string" && event.data.length > 1_000_000) {
            console.warn("[WebSocket] Received message string exceeds 1MB, ignoring");
            return;
          }

          const message: WebSocketMessage = JSON.parse(event.data);

          console.log("[WebSocket] Received message");

          if (message.type === "pong") {
            console.log("[WebSocket] Received pong");
            return;
          }

          callbacksRef.current.onMessage?.(message);
        } catch (error) {
          console.error("[WebSocket] Error parsing message:", error);
        }
      };

      wsRef.current.onclose = (event) => {
        console.log(
          `[WebSocket] Disconnected - Code: ${event.code}, Reason: ${event.reason}`
        );

        wsRef.current = null;
        setConnectionState("disconnected");
        stopHeartbeat();
        callbacksRef.current.onDisconnect?.();

        if (!isManualDisconnectRef.current) {
          if (event.code !== 1000 && event.code !== 1001) {
            console.log(
              "[WebSocket] Abnormal closure, attempting to reconnect..."
            );
            scheduleReconnect();
          } else {
            console.log("[WebSocket] Normal closure, not reconnecting");
          }
        }
      };

      wsRef.current.onerror = (error) => {
        console.error("[WebSocket] Connection error:", error);
        setConnectionState("error");
        callbacksRef.current.onError?.(error);
      };
    } catch (error) {
      console.error("[WebSocket] Error creating WebSocket:", error);
      setConnectionState("error");
      scheduleReconnect();
    }
  }, [url, startHeartbeat, stopHeartbeat, scheduleReconnect]);

  const disconnect = useCallback(() => {
    console.log("[WebSocket] Manual disconnect requested");
    isManualDisconnectRef.current = true;

    if (reconnectTimeoutRef.current) {
      window.clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    stopHeartbeat();

    if (wsRef.current) {
      wsRef.current.close(1000, "Manual disconnect");
      wsRef.current = null;
    }

    setConnectionState("disconnected");
    reconnectAttemptsRef.current = 0;
  }, [stopHeartbeat]);

  const sendMessage = useCallback(
    (message: any) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        try {
          const messageStr = JSON.stringify(message);
          console.log("[WebSocket] Sending message");
          wsRef.current.send(messageStr);
          return true;
        } catch (error) {
          console.error("[WebSocket] Error sending message:", error);
          return false;
        }
      }

      console.warn(
        `[WebSocket] Cannot send message - Connection state: ${connectionState}`
      );
      return false;
    },
    [connectionState]
  );

  const forceReconnect = useCallback(() => {
    console.log("[WebSocket] Force reconnect requested");
    isManualDisconnectRef.current = false;
    reconnectAttemptsRef.current = 0;

    disconnect();

    setTimeout(() => {
      isManualDisconnectRef.current = false;
      connect();
    }, 1000);
  }, [disconnect, connect]);

  // Stop warming while the tab is hidden. When it becomes visible again, warm right away,
  // reconnecting first if API Gateway closed the idle connection in the meantime.
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState !== "visible") {
        stopHeartbeat();
        return;
      }

      if (wsRef.current?.readyState === WebSocket.OPEN) {
        startHeartbeat();
      } else if (url && !isManualDisconnectRef.current) {
        reconnectAttemptsRef.current = 0;
        connect();
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [url, connect, startHeartbeat, stopHeartbeat]);

  // Only depend on URL changes, not callback changes
  useEffect(() => {
    if (url) {
      isManualDisconnectRef.current = false;
      connect();
    }

    return () => {
      isManualDisconnectRef.current = true;
      disconnect();
    };
  }, [url]); // Only URL dependency!

  const isConnected = wsRef.current?.readyState === WebSocket.OPEN;

  return {
    sendMessage,
    connect,
    disconnect,
    forceReconnect,
    isConnected,
    connectionState,
  };
};
