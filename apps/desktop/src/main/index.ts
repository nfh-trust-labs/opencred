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

import { app, BrowserWindow, Menu, type MenuItemConstructorOptions } from "electron";
import * as path from "node:path";
import { registerIpcHandlers, cleanupIpcHandlers } from "./ipc-handlers.js";
import { initStore } from "./store.js";

let mainWindow: BrowserWindow | null = null;

const IS_DEV = !app.isPackaged;
const DEV_SERVER_URL = "http://localhost:5174";

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: "OpenCred",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    show: false,
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

function buildAppMenu(): void {
  const template: MenuItemConstructorOptions[] = [
    {
      label: "File",
      submenu: [
        {
          label: "Open Credential...",
          accelerator: "CmdOrCtrl+O",
          click: () => {
            mainWindow?.webContents.send("menu:open-file");
          },
        },
        {
          label: "Save Credential...",
          accelerator: "CmdOrCtrl+S",
          click: () => {
            mainWindow?.webContents.send("menu:save-file");
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
      submenu: [
        { role: "reload" },
        { role: "forceReload" },
        { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },
    {
      label: "Window",
      submenu: [{ role: "minimize" }, { role: "close" }],
    },
  ];

  // macOS gets a special first menu with the app name.
  if (process.platform === "darwin") {
    template.unshift({
      label: app.name,
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

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

app.whenReady().then(() => {
  initStore();
  registerIpcHandlers();
  buildAppMenu();
  createWindow();

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
  cleanupIpcHandlers();
});
