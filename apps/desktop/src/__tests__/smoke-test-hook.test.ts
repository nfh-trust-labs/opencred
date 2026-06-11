/**
 * Tests for the packaged-app smoke-test hook (installSmokeTestHook).
 *
 * The hook is the in-app half of the packaged boot smoke test (see
 * scripts/packaged-smoke.mjs and .github/workflows/desktop-smoke.yml). These
 * tests drive it with a fake BrowserWindow to verify the protocol:
 *
 *  - success (ready-to-show + did-finish-load + #root mounted)
 *    → "[smoke] renderer loaded <url>" on stdout, app.exit(0)
 *  - did-fail-load / render-process-gone / empty #root
 *    → "[smoke] FAIL: ..." on stdout, app.exit(1)
 *
 * The real GUI boot path is exercised in CI against the electron-builder
 * --dir output.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { BrowserWindow } from "electron";

const appExit = vi.fn();

// Mock electron before importing the main module (same pattern as
// menu.test.ts — we never boot a real app).
vi.mock("electron", () => ({
  app: {
    isPackaged: true,
    name: "OpenCred-Test",
    whenReady: vi.fn(() => Promise.resolve()),
    on: vi.fn(),
    getPath: vi.fn(() => "/tmp"),
    setPath: vi.fn(),
    exit: (code: number) => appExit(code),
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

const { installSmokeTestHook } = await import("../main/index.js");

const PROD_URL =
  "file:///Applications/OpenCred.app/Contents/Resources/app.asar/renderer/index.html";

type Listener = (...args: unknown[]) => void;

/** Minimal fake of the BrowserWindow surface the hook touches. */
function makeFakeWindow(options: { mounted?: unknown; execError?: Error; url?: string } = {}) {
  const winListeners = new Map<string, Listener>();
  const wcListeners = new Map<string, Listener>();

  const fake = {
    once: (event: string, listener: Listener) => {
      winListeners.set(event, listener);
    },
    webContents: {
      once: (event: string, listener: Listener) => {
        wcListeners.set(event, listener);
      },
      on: (event: string, listener: Listener) => {
        wcListeners.set(event, listener);
      },
      executeJavaScript: vi.fn(() =>
        options.execError
          ? Promise.reject(options.execError)
          : Promise.resolve(options.mounted ?? true),
      ),
      getURL: () => options.url ?? PROD_URL,
    },
    emitWindow: (event: string, ...args: unknown[]) => {
      winListeners.get(event)?.(...args);
    },
    emitWebContents: (event: string, ...args: unknown[]) => {
      wcListeners.get(event)?.(...args);
    },
  };
  return fake;
}

let stdoutLines: string[] = [];
let stdoutSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  appExit.mockClear();
  stdoutLines = [];
  // Capture the hook's stdout protocol line and invoke the flush callback so
  // finish() proceeds to app.exit.
  stdoutSpy = vi
    .spyOn(process.stdout, "write")
    .mockImplementation(
      (
        chunk: Uint8Array | string,
        encodingOrCb?: BufferEncoding | ((err?: Error | null) => void),
        cb?: (err?: Error | null) => void,
      ): boolean => {
        stdoutLines.push(String(chunk));
        const callback = typeof encodingOrCb === "function" ? encodingOrCb : cb;
        callback?.(null);
        return true;
      },
    );
});

afterEach(() => {
  stdoutSpy.mockRestore();
  vi.useRealTimers();
});

describe("installSmokeTestHook", () => {
  it("prints the renderer URL and exits 0 when the production renderer mounts", async () => {
    const win = makeFakeWindow({ mounted: true });
    installSmokeTestHook(win as unknown as BrowserWindow);

    win.emitWindow("ready-to-show");
    win.emitWebContents("did-finish-load");

    await vi.waitFor(() => expect(appExit).toHaveBeenCalledWith(0));
    const line = stdoutLines.join("");
    expect(line).toContain(`[smoke] renderer loaded ${PROD_URL}`);
  });

  it("does not verify until BOTH ready-to-show and did-finish-load fired", async () => {
    const win = makeFakeWindow({ mounted: true });
    installSmokeTestHook(win as unknown as BrowserWindow);

    win.emitWindow("ready-to-show");
    // did-finish-load never fires — no verification, no exit.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(win.webContents.executeJavaScript).not.toHaveBeenCalled();
    expect(appExit).not.toHaveBeenCalled();
  });

  it("exits 1 when the renderer loaded but #root never mounted", async () => {
    const win = makeFakeWindow({ mounted: false });
    installSmokeTestHook(win as unknown as BrowserWindow);

    win.emitWindow("ready-to-show");
    win.emitWebContents("did-finish-load");

    await vi.waitFor(() => expect(appExit).toHaveBeenCalledWith(1));
    expect(stdoutLines.join("")).toContain("#root is empty");
  });

  it("exits 1 on did-fail-load", () => {
    const win = makeFakeWindow();
    installSmokeTestHook(win as unknown as BrowserWindow);

    win.emitWebContents("did-fail-load", {}, -6, "ERR_FILE_NOT_FOUND", "file:///missing.html");

    expect(appExit).toHaveBeenCalledWith(1);
    const line = stdoutLines.join("");
    expect(line).toContain("[smoke] FAIL: did-fail-load");
    expect(line).toContain("ERR_FILE_NOT_FOUND");
  });

  it("exits 1 on render-process-gone", () => {
    const win = makeFakeWindow();
    installSmokeTestHook(win as unknown as BrowserWindow);

    win.emitWebContents("render-process-gone", {}, { reason: "crashed" });

    expect(appExit).toHaveBeenCalledWith(1);
    expect(stdoutLines.join("")).toContain("render-process-gone (crashed)");
  });

  it("exits 1 when executeJavaScript rejects", async () => {
    const win = makeFakeWindow({ execError: new Error("page destroyed") });
    installSmokeTestHook(win as unknown as BrowserWindow);

    win.emitWindow("ready-to-show");
    win.emitWebContents("did-finish-load");

    await vi.waitFor(() => expect(appExit).toHaveBeenCalledWith(1));
    expect(stdoutLines.join("")).toContain("page destroyed");
  });

  it("times out with exit 1 if the renderer never loads", () => {
    vi.useFakeTimers();
    const win = makeFakeWindow();
    installSmokeTestHook(win as unknown as BrowserWindow);

    vi.advanceTimersByTime(30_000);

    expect(appExit).toHaveBeenCalledWith(1);
    expect(stdoutLines.join("")).toContain("timed out after 30s");
  });

  it("settles only once — a late failure after success is ignored", async () => {
    const win = makeFakeWindow({ mounted: true });
    installSmokeTestHook(win as unknown as BrowserWindow);

    win.emitWindow("ready-to-show");
    win.emitWebContents("did-finish-load");
    await vi.waitFor(() => expect(appExit).toHaveBeenCalledWith(0));

    win.emitWebContents("render-process-gone", {}, { reason: "crashed" });
    expect(appExit).toHaveBeenCalledTimes(1);
  });
});
