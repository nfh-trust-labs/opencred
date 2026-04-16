/**
 * Tests for the app menu template (MED-03).
 *
 * The `toggleDevTools` menu role exposes the renderer's JS console to anyone
 * who can reach the app's menu bar. In production builds that's a
 * privilege-escalation vector — an attacker with momentary physical access
 * (or, in a kiosk deployment, any end user) can drop into DevTools, inspect
 * session data, and call preload APIs.
 *
 * These tests verify that `createAppMenuTemplate` omits `toggleDevTools`
 * when `isDev = false` and keeps it when `isDev = true`.
 */

import { describe, it, expect, vi } from "vitest";

// Mock electron before importing the main module. The test only cares about
// the template shape — it doesn't need BrowserWindow or any window.
vi.mock("electron", () => ({
  app: {
    isPackaged: true,
    name: "OpenCred-Test",
    whenReady: vi.fn(() => Promise.resolve()),
    on: vi.fn(),
    getPath: vi.fn(() => "/tmp"),
  },
  BrowserWindow: vi.fn(),
  Menu: {
    setApplicationMenu: vi.fn(),
    buildFromTemplate: vi.fn(),
  },
  session: {
    defaultSession: {
      webRequest: { onHeadersReceived: vi.fn() },
      setPermissionRequestHandler: vi.fn(),
    },
  },
}));

// Everything downstream of index.ts — we don't actually boot the app.
vi.mock("../main/ipc-handlers.js", () => ({
  registerIpcHandlers: vi.fn(),
  cleanupIpcHandlers: vi.fn(),
  mergeReloadedSigners: vi.fn(),
}));

vi.mock("../main/store.js", () => ({
  initStore: vi.fn(),
  getStore: vi.fn(() => ({ get: vi.fn(), set: vi.fn() })),
}));

vi.mock("../main/persisted-signer-loader.js", () => ({
  reloadPersistedSigners: vi.fn(() => ({ metadata: new Map(), signers: new Map() })),
}));

vi.mock("../main/auto-updater.js", () => ({
  initAutoUpdater: vi.fn(),
  cleanupAutoUpdater: vi.fn(),
}));

vi.mock("../main/document-loader-with-cache.js", () => ({
  installCustomContextResolver: vi.fn(),
  uninstallCustomContextResolver: vi.fn(),
}));

vi.mock("../main/logger.js", () => ({
  createLogger: vi.fn(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  })),
}));

vi.mock("@opencred/schema-engine", () => ({
  createRegistryWithUpdates: vi.fn(async () => ({ listSchemas: () => [] })),
}));

vi.mock("../main/schema-registry-singleton.js", () => ({
  setSchemaRegistry: vi.fn(),
}));

const { createAppMenuTemplate } = await import("../main/index.js");

describe("createAppMenuTemplate (MED-03)", () => {
  function findViewSubmenu(
    template: ReturnType<typeof createAppMenuTemplate>,
  ): unknown[] {
    const view = template.find((entry) => entry.label === "View");
    if (!view || !Array.isArray(view.submenu)) {
      throw new Error("View submenu not found");
    }
    return view.submenu;
  }

  function hasToggleDevToolsRole(submenu: unknown[]): boolean {
    return submenu.some(
      (item) => typeof item === "object" && item !== null && "role" in item
        ? (item as { role?: string }).role === "toggleDevTools"
        : false,
    );
  }

  it("omits toggleDevTools from the View menu in production (isDev=false)", () => {
    const template = createAppMenuTemplate(false, "linux");
    const view = findViewSubmenu(template);
    expect(hasToggleDevToolsRole(view)).toBe(false);
  });

  it("includes toggleDevTools in the View menu in development (isDev=true)", () => {
    const template = createAppMenuTemplate(true, "linux");
    const view = findViewSubmenu(template);
    expect(hasToggleDevToolsRole(view)).toBe(true);
  });

  it("omits toggleDevTools regardless of platform when isDev=false", () => {
    for (const platform of ["darwin", "linux", "win32"] as const) {
      const template = createAppMenuTemplate(false, platform);
      const view = findViewSubmenu(template);
      expect(hasToggleDevToolsRole(view)).toBe(false);
    }
  });

  it("includes a macOS-specific first submenu only on darwin", () => {
    const onDarwin = createAppMenuTemplate(false, "darwin", { appName: "TestApp" });
    expect(onDarwin[0].label).toBe("TestApp");

    const onLinux = createAppMenuTemplate(false, "linux");
    expect(onLinux[0].label).toBe("File");
  });

  it("preserves the rest of the View submenu (reload, zoom, fullscreen)", () => {
    const template = createAppMenuTemplate(false, "linux");
    const view = findViewSubmenu(template);
    const roles = view
      .map((item) =>
        typeof item === "object" && item !== null && "role" in item
          ? (item as { role?: string }).role
          : undefined,
      )
      .filter((r): r is string => r !== undefined);

    expect(roles).toContain("reload");
    expect(roles).toContain("forceReload");
    expect(roles).toContain("resetZoom");
    expect(roles).toContain("togglefullscreen");
  });
});
