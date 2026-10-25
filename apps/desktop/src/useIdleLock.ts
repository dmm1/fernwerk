import { useEffect, useRef } from "react";

const ACTIVITY_EVENTS = ["keydown", "mousedown", "mousemove", "wheel", "touchstart"] as const;

/** Calls `onIdle` once after `timeoutMs` without keyboard, mouse or touch input. */
export function useIdleLock(enabled: boolean, timeoutMs: number, onIdle: () => void) {
  const lastActivity = useRef(Date.now());
  const onIdleRef = useRef(onIdle);
  onIdleRef.current = onIdle;

  useEffect(() => {
    if (!enabled) return;
    lastActivity.current = Date.now();
    const touch = () => {
      lastActivity.current = Date.now();
    };
    ACTIVITY_EVENTS.forEach((e) => window.addEventListener(e, touch, { passive: true, capture: true }));
    const timer = window.setInterval(() => {
      if (Date.now() - lastActivity.current >= timeoutMs) onIdleRef.current();
    }, 5_000);
    return () => {
      window.clearInterval(timer);
      ACTIVITY_EVENTS.forEach((e) => window.removeEventListener(e, touch, { capture: true }));
    };
  }, [enabled, timeoutMs]);
}
