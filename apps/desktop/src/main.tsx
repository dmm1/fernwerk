import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ThemeProvider } from "@dmm1/daemon-ui";
import { App } from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider defaultTheme="dark" storageKey="fernwerk-theme">
      <App />
    </ThemeProvider>
  </StrictMode>,
);
