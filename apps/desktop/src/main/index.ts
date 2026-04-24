/**
 * Electron main process entry point.
 *
 * Responsibilities:
 *  - Create and manage the BrowserWindow
 *  - Set up the application menu
 *  - Register IPC handlers (delegated to ipc-handlers.ts)
 *  - Initialise electron-store for local config persistence
 *  - Handle graceful shutdown
 *
 * SECURITY NOTES:
 *  - nodeIntegration is disabled; contextIsolation is enabled
 *  - The renderer communicates with the main process exclusively via the
 *    preload script and contextBridge (see preload.ts)
 *  - Private keys are handled only in the main process and NEVER logged
 */

import { app, BrowserWindow, Menu, session, type MenuItemConstructorOptions } from "electron";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import { registerIpcHandlers, cleanupIpcHandlers, mergeReloadedSigners } from "./ipc-handlers.js";
import { initStore, getStore } from "./store.js";
import { reloadPersistedSigners } from "./persisted-signer-loader.js";
import { initAutoUpdater, cleanupAutoUpdater } from "./auto-updater.js";
import {
  installCustomContextResolver,
  uninstallCustomContextResolver,
} from "./document-loader-with-cache.js";
import { createLogger } from "./logger.js";
import { createRegistryWithUpdates, Validator } from "@opencred/schema-engine";
import { setSchemaRegistry } from "./schema-registry-singleton.js";
import { setValidator } from "./validator-singleton.js";
import { setPkcs11Logger } from "@opencred/signing";

// ---------------------------------------------------------------------------
// Global crash handlers — catch unhandled errors before app.whenReady()
// ---------------------------------------------------------------------------

const logger = createLogger("main");

// Route PKCS#11 warnings (C_Finalize failures, unreadable keys, etc.) to the
// desktop Pino logger. Previously these hit console.warn in the packages/signing
// code, which was invisible to aggregated log collectors and couldn't be
// filtered by LOG_LEVEL. See Anand's P2-09.
const pkcs11Logger = createLogger("pkcs11");
setPkcs11Logger({
  warn: (msg: string, meta?: Record<string, unknown>) => pkcs11Logger.warn(msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => pkcs11Logger.error(msg, meta),
});

process.on("uncaughtException", (error) => {
  logger.error("Uncaught exception", { error: error.message, stack: error.stack });
});

process.on("unhandledRejection", (reason) => {
  const msg = reason instanceof Error ? reason.message : String(reason);
  logger.error("Unhandled rejection", { reason: msg });
});

let mainWindow: BrowserWindow | null = null;

const IS_DEV = !app.isPackaged;
const DEV_SERVER_URL = "http://localhost:5174";

function createWindow(): void {
  const preloadPath = path.join(__dirname, "..", "..", "preload", "main", "preload.cjs");
  logger.debug("Preload path resolved", { preloadPath });
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: "OpenCred",
    webPreferences: {
      preload: preloadPath,
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    show: false,
  });

  // -------------------------------------------------------------------------
  // Content Security Policy — set via session headers so it applies before
  // any content is loaded.  In dev mode we allow connect-src to localhost for
  // Vite HMR; in production the policy is strict same-origin.
  // -------------------------------------------------------------------------
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "Content-Security-Policy": [
          IS_DEV
            ? "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self'; connect-src 'self' http://localhost:* ws://localhost:*; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            : "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ],
      },
    });
  });

  // -------------------------------------------------------------------------
  // Permission handler: allow camera access for QR code scanning.
  // -------------------------------------------------------------------------
  session.defaultSession.setPermissionRequestHandler(
    (_webContents, permission, callback, details) => {
      // `details` is a discriminated union; `mediaTypes` only exists on
      // the media-access variant. Narrow explicitly before accessing.
      if (
        permission === "media" &&
        "mediaTypes" in details &&
        details.mediaTypes?.includes("video")
      ) {
        callback(true);
        return;
      }
      callback(false);
    },
  );

  // -------------------------------------------------------------------------
  // Navigation guard — prevent the renderer from navigating away from the app.
  // In dev mode we allow navigation to the Vite dev server.
  // -------------------------------------------------------------------------
  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (IS_DEV && url.startsWith(DEV_SERVER_URL)) return;
    event.preventDefault();
    try {
      logger.warn("Blocked navigation attempt", { url: new URL(url).origin });
    } catch {
      logger.warn("Blocked navigation attempt");
    }
  });

  // -------------------------------------------------------------------------
  // Block window.open — the app should never open new windows.
  // -------------------------------------------------------------------------
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    try {
      logger.warn("Blocked window.open attempt", { url: new URL(url).origin });
    } catch {
      logger.warn("Blocked window.open attempt");
    }
    return { action: "deny" };
  });

  // Forward renderer console to main process stdout for debugging.
  mainWindow.webContents.on("console-message", (_ev, _level, message) => {
    logger.debug("[renderer] " + message);
  });

  // Show the window once the renderer is ready to avoid a blank flash.
  mainWindow.once("ready-to-show", () => {
    mainWindow?.show();
  });

  if (IS_DEV) {
    void mainWindow.loadURL(DEV_SERVER_URL);
    // Open DevTools in development mode.
    mainWindow.webContents.openDevTools({ mode: "detach" });
  } else {
    const rendererIndex = path.join(__dirname, "..", "..", "renderer", "index.html");
    void mainWindow.loadFile(rendererIndex);
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

/**
 * Build the application menu template.
 *
 * Exported so tests can assert its shape without touching the Menu module.
 *
 * @param isDev - Whether the app is running in a development build. Gates the
 *   `toggleDevTools` entry: MED-03 found that production builds exposed DevTools
 *   via a visible menu item, which would let an attacker with momentary UI
 *   access drop into the renderer's JavaScript context. In production the View
 *   submenu now omits the DevTools toggle entirely.
 * @param platform - Normally `process.platform`; made parameterizable so tests
 *   can assert the macOS-specific leading submenu.
 * @param options - Optional callbacks for the File menu actions. Defaults are
 *   wired to the BrowserWindow via `webContents.send` in production.
 */
export function createAppMenuTemplate(
  isDev: boolean,
  platform: NodeJS.Platform = process.platform,
  options: {
    onOpenFile?: () => void;
    onSaveFile?: () => void;
    appName?: string;
  } = {},
): MenuItemConstructorOptions[] {
  const { onOpenFile, onSaveFile, appName } = options;

  const viewSubmenu: MenuItemConstructorOptions[] = [
    { role: "reload" },
    { role: "forceReload" },
    ...(isDev ? [{ role: "toggleDevTools" as const }] : []),
    { type: "separator" },
    { role: "resetZoom" },
    { role: "zoomIn" },
    { role: "zoomOut" },
    { type: "separator" },
    { role: "togglefullscreen" },
  ];

  const template: MenuItemConstructorOptions[] = [
    {
      label: "File",
      submenu: [
        {
          label: "Open Credential...",
          accelerator: "CmdOrCtrl+O",
          click: () => {
            onOpenFile?.();
          },
        },
        {
          label: "Save Credential...",
          accelerator: "CmdOrCtrl+S",
          click: () => {
            onSaveFile?.();
          },
        },
        { type: "separator" },
        { role: "quit" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
      ],
    },
    {
      label: "View",
      submenu: viewSubmenu,
    },
    {
      label: "Window",
      submenu: [{ role: "minimize" }, { role: "close" }],
    },
  ];

  // macOS gets a special first menu with the app name.
  if (platform === "darwin") {
    template.unshift({
      label: appName ?? "OpenCred",
      submenu: [
        { role: "about" },
        { type: "separator" },
        { role: "services" },
        { type: "separator" },
        { role: "hide" },
        { role: "hideOthers" },
        { role: "unhide" },
        { type: "separator" },
        { role: "quit" },
      ],
    });
  }

  return template;
}

function buildAppMenu(): void {
  const template = createAppMenuTemplate(IS_DEV, process.platform, {
    onOpenFile: () => {
      mainWindow?.webContents.send("menu:open-file");
    },
    onSaveFile: () => {
      mainWindow?.webContents.send("menu:save-file");
    },
    appName: app.name,
  });

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

app.whenReady().then(async () => {
  logger.info("App ready, initialising");
  initStore();

  // Schema registry with optional remote updates
  const store = getStore();
  const schemaRegistry = await createRegistryWithUpdates({
    manifestUrl: (store.get("schemaUpdateUrl") as string | undefined) ?? undefined,
    cacheDir: path.join(app.getPath("userData"), "schemas"),
    logger: { info: logger.info.bind(logger), warn: logger.warn.bind(logger) },
  });
  setSchemaRegistry(schemaRegistry);
  setValidator(new Validator(schemaRegistry));
  logger.info("Schema registry initialised", { count: schemaRegistry.listSchemas().length });

  // Register the process-wide JSON-LD document loader extension so that
  // user-provided custom-schema contexts (cached in electron-store) are
  // resolvable by @opencred/crypto's canonicalization step. This must run
  // BEFORE any signing/verification can occur — i.e. before IPC handlers
  // are registered.
  installCustomContextResolver();

  registerIpcHandlers();

  // Reload previously imported signing keys from disk.
  const reloaded = reloadPersistedSigners(getStore());
  mergeReloadedSigners(reloaded);

  buildAppMenu();
  createWindow();
  logger.info("Window created");

  // Initialise auto-updater after the window is ready (checks GitHub Releases).
  if (!IS_DEV) {
    initAutoUpdater();
  }

  app.on("activate", () => {
    // macOS: re-create the window when the dock icon is clicked and no windows exist.
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", () => {
  logger.info("App shutting down");
  cleanupAutoUpdater();
  cleanupIpcHandlers();
  uninstallCustomContextResolver();
});
