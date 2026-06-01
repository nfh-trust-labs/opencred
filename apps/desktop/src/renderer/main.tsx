import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

// Tag the root for platform-specific chrome. On macOS the native title bar is
// hidden (titleBarStyle: "hiddenInset" in the main process) and the custom top
// bar must reserve space for the overlaid traffic lights. Detected off the
// user-agent so it's synchronous (no layout flash) and touches no IPC surface.
if (navigator.userAgent.includes("Macintosh")) {
  document.documentElement.classList.add("platform-darwin");
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
