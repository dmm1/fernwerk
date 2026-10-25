import { getCurrentWindow } from "@tauri-apps/api/window";

const appWindow = getCurrentWindow();

export function TitleBar() {
  return (
    <header className="titlebar" data-tauri-drag-region="deep">
      <div className="traffic-lights">
        <button
          type="button"
          className="traffic close"
          onClick={() => void appWindow.close()}
          aria-label="Close window"
          title="Close"
        >
          <span aria-hidden="true">×</span>
        </button>
        <button
          type="button"
          className="traffic minimize"
          onClick={() => void appWindow.minimize()}
          aria-label="Minimize window"
          title="Minimize"
        >
          <span aria-hidden="true">−</span>
        </button>
        <button
          type="button"
          className="traffic maximize"
          onClick={() => void appWindow.toggleMaximize()}
          aria-label="Maximize window"
          title="Maximize"
        >
          <span aria-hidden="true">+</span>
        </button>
      </div>
      <span className="titlebar-title">Fernwerk</span>
    </header>
  );
}
