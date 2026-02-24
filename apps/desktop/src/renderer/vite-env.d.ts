/// <reference types="vite/client" />

import type { OpenCredDesktopAPI } from "../shared/ipc-types";

declare global {
  interface Window {
    /** Exposed by the preload script via contextBridge. */
    opencred: OpenCredDesktopAPI;
  }
}
