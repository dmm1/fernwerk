import { useEffect, useImperativeHandle, useRef, type Ref } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "@xterm/xterm/css/xterm.css";

export interface TerminalHandle {
  write(data: Uint8Array | string): void;
  size(): { cols: number; rows: number };
  focus(): void;
}

export interface TerminalProps {
  ref?: Ref<TerminalHandle>;
  /** Keystrokes and pastes, already encoded as UTF-8 bytes. */
  onInput?: (data: Uint8Array<ArrayBuffer>) => void;
  onResize?: (size: { cols: number; rows: number }) => void;
  /**
   * Called when the user clicks a link in the output. Only http(s) URLs are passed
   * on; without this prop links do nothing, since the output is untrusted.
   */
  onLink?: (url: string) => void;
  className?: string;
}

const encoder = new TextEncoder();

function isWebUrl(text: string): boolean {
  try {
    const { protocol } = new URL(text);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}

export function Terminal({ ref, onInput, onResize, onLink, className }: TerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  // Keep the latest callbacks without re-creating the terminal.
  const callbacks = useRef({ onInput, onResize, onLink });
  callbacks.current = { onInput, onResize, onLink };

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Links come from the remote server. Never let xterm open them itself (that
    // would load them inside the app); hand only web URLs to the caller.
    const openLink = (_event: MouseEvent, text: string) => {
      if (isWebUrl(text)) callbacks.current.onLink?.(text);
    };
    const term = new XTerm({
      cursorBlink: true,
      fontFamily: '"Cascadia Code", "JetBrains Mono", Menlo, Consolas, monospace',
      fontSize: 14,
      scrollback: 10_000,
      allowProposedApi: true,
      // OSC 8 hyperlinks.
      linkHandler: { activate: openLink, allowNonHttpProtocols: false },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon(openLink));
    term.open(container);
    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      term.loadAddon(webgl);
    } catch {
      // WebGL unavailable: xterm falls back to the DOM renderer.
    }
    fit.fit();

    const subs = [
      term.onData((d) => callbacks.current.onInput?.(encoder.encode(d))),
      // Binary input (some mouse reports) is a latin1 string, not UTF-8.
      term.onBinary((d) =>
        callbacks.current.onInput?.(Uint8Array.from(d, (c) => c.charCodeAt(0))),
      ),
      term.onResize((s) => callbacks.current.onResize?.(s)),
    ];
    const observer = new ResizeObserver(() => fit.fit());
    observer.observe(container);
    termRef.current = term;

    return () => {
      observer.disconnect();
      subs.forEach((s) => s.dispose());
      term.dispose();
      termRef.current = null;
    };
  }, []);

  useImperativeHandle(
    ref,
    () => ({
      write: (data) => termRef.current?.write(data),
      size: () => ({
        cols: termRef.current?.cols ?? 80,
        rows: termRef.current?.rows ?? 24,
      }),
      focus: () => termRef.current?.focus(),
    }),
    [],
  );

  return <div ref={containerRef} className={className} style={{ height: "100%", width: "100%" }} />;
}
