/**
 * Tests for BrowserWindow hardening (#334).
 *
 * Verifies that `createWindow()` applies the secure defaults required by
 * Electrons security checklist and by the issue:
 *  - sandbox: true in webPreferences
 *  - setWindowOpenHandler that denies everything
 *  - will-navigate listener that blocks navigation away from the loaded index
 *  - A strict Content-Security-Policy injected via onHeadersReceived
 */

import { describe, it, expect, vi, beforeAll } from "vitest";
import * as os from "node:os";

// -----------------------------------------------------------------------
// Capture state from the mocks
// -----------------------------------------------------------------------

interface CapturedWebContents {
  session: { webRequest: { onHeadersReceived: ReturnType<typeof vi.fn> } };
  setWindowOpenHandler: ReturnType<typeof vi.fn>;
  on: ReturnType<typeof vi.fn>;
  getURL: ReturnType<typeof vi.fn>;
  loadURL: ReturnType<typeof vi.fn>;
  loadFile: ReturnType<typeof vi.fn>;
  openDevTools: ReturnType<typeof vi.fn>;
}

interface CapturedWindow {
  webPreferences: Record<string, unknown> | undefined;
  webContents: CapturedWebContents;
  once: ReturnType<typeof vi.fn>;
  on: ReturnType<typeof vi.fn>;
  show: ReturnType<typeof vi.fn>;
  loadURL: ReturnType<typeof vi.fn>;
  loadFile: ReturnType<typeof vi.fn>;
}

let captured: CapturedWindow | null = null;

vi.mock("electron", () => {
  const makeWebContents = (): CapturedWebContents => ({
    session: { webRequest: { onHeadersReceived: vi.fn() } },
    setWindowOpenHandler: vi.fn(),
    on: vi.fn(),
    getURL: vi.fn(() => "file:///renderer/index.html"),
    loadURL: vi.fn(),
    loadFile: vi.fn(),
    openDevTools: vi.fn(),
  });

  class FakeBrowserWindow {
    public webPreferences: Record<string, unknown> | undefined;
    public webContents: CapturedWebContents;
    public once = vi.fn();
    public on = vi.fn();
    public show = vi.fn();
    public loadURL = vi.fn();
    public loadFile = vi.fn();
    constructor(opts: { webPreferences?: Record<string, unknown> }) {
      this.webPreferences = opts.webPreferences;
      this.webContents = makeWebContents();
      captured = {
        webPreferences: this.webPreferences,
        webContents: this.webContents,
        once: this.once,
        on: this.on,
        show: this.show,
        loadURL: this.loadURL,
        loadFile: this.loadFile,
      };
    }
    static getAllWindows() {
      return [];
    }
  }

  const neverResolving = new Promise<void>(() => {});

  return {
    app: {
      whenReady: vi.fn(() => neverResolving),
      on: vi.fn(),
      isPackaged: false,
      getPath: vi.fn((name: string) => {
        if (name === "userData") return os.tmpdir();
        if (name === "logs") return os.tmpdir();
        return os.tmpdir();
      }),
      getName: vi.fn(() => "opencred-test"),
      getVersion: vi.fn(() => "0.1.0-test"),
      quit: vi.fn(),
      name: "opencred-test",
    },
    BrowserWindow: FakeBrowserWindow,
    Menu: {
      buildFromTemplate: vi.fn((template) => template),
      setApplicationMenu: vi.fn(),
    },
    ipcMain: {
      handle: vi.fn(),
      removeHandler: vi.fn(),
    },
    dialog: {
      showOpenDialog: vi.fn(),
      showSaveDialog: vi.fn(),
    },
    safeStorage: {
      isEncryptionAvailable: vi.fn(() => false),
      encryptString: vi.fn((s: string) => Buffer.from(s)),
      decryptString: vi.fn((b: Buffer) => b.toString()),
    },
  };
});

vi.mock("electron-updater", () => ({
  default: { autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() } },
  autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() },
}));

vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => ({
    get: vi.fn(() => undefined),
    set: vi.fn(),
    store: {},
    path: "/tmp/test-store",
  })),
}));

vi.mock("@opencred/dedi-client", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    createPublishManager: vi.fn(() => ({
      ensureSchemaPublished: vi.fn(),
      publishDIDDocument: vi.fn(),
      ensureRegistries: vi.fn(),
      getPublishedSchemaIds: () => [],
    })),
    DeDiPublishManager: vi.fn(),
  };
});

vi.mock("../signing/os-cert-provider", () => ({
  listOsCertificates: vi.fn(async () => []),
  signWithOsCert: vi.fn(),
}));

vi.mock("@opencred/signing/pkcs11-loader", () => ({
  loadPkcs11js: () => ({ PKCS11: class {} }),
}));

vi.mock("keytar", () => ({
  getPassword: vi.fn(async () => null),
  setPassword: vi.fn(async () => {}),
  deletePassword: vi.fn(async () => true),
}));

let createWindow: () => void;

beforeAll(async () => {
  // Init the store before the module registers IPC handlers.
  const store = await import("../main/store");
  store.initStore();
  const mod = await import("../main/index");
  createWindow = mod.createWindow;
});

describe("BrowserWindow hardening (#334)", () => {
  it("creates the window with contextIsolation and sandbox enabled", () => {
    captured = null;
    createWindow();
    expect(captured).not.toBeNull();
    expect(captured!.webPreferences?.contextIsolation).toBe(true);
    expect(captured!.webPreferences?.nodeIntegration).toBe(false);
    // The core #334 change:
    expect(captured!.webPreferences?.sandbox).toBe(true);
  });

  it("installs a Content-Security-Policy header on all responses", () => {
    captured = null;
    createWindow();
    expect(captured).not.toBeNull();
    const hook = captured!.webContents.session.webRequest.onHeadersReceived;
    expect(hook).toHaveBeenCalledTimes(1);

    // Invoke the header-injection callback with a fake response and check
    // that CSP is added.
    const callback = hook.mock.calls[0][0] as (
      details: { responseHeaders?: Record<string, string[]> },
      done: (res: { responseHeaders?: Record<string, string[]> }) => void,
    ) => void;
    let applied: Record<string, string[]> | undefined;
    callback({ responseHeaders: { "X-Test": ["ok"] } }, (res) => {
      applied = res.responseHeaders;
    });
    expect(applied).toBeDefined();
    expect(applied?.["Content-Security-Policy"]).toBeDefined();
    const csp = applied?.["Content-Security-Policy"]?.[0] ?? "";
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    // Test env is dev-like (isPackaged: false), so unsafe-eval is allowed
    // for Vite HMR — but default-src and script-src must still lock to self.
    expect(applied?.["X-Test"]).toEqual(["ok"]);
  });

  it("denies all window.open calls via setWindowOpenHandler", () => {
    captured = null;
    createWindow();
    const setWindowOpenHandler = captured!.webContents.setWindowOpenHandler;
    expect(setWindowOpenHandler).toHaveBeenCalledTimes(1);
    const handlerFn = setWindowOpenHandler.mock.calls[0][0] as (
      details: { url: string },
    ) => { action: string };
    expect(handlerFn({ url: "https://evil.example" }).action).toBe("deny");
    expect(handlerFn({ url: "about:blank" }).action).toBe("deny");
  });

  it("registers a will-navigate listener that blocks cross-origin navigation", () => {
    captured = null;
    createWindow();
    const onFn = captured!.webContents.on;
    // Find the will-navigate call — there may also be console-message.
    const willNavigateCall = onFn.mock.calls.find(
      (c: unknown[]) => c[0] === "will-navigate",
    );
    expect(willNavigateCall).toBeDefined();
    const listener = willNavigateCall![1] as (
      event: { preventDefault: () => void },
      url: string,
    ) => void;
    const event = { preventDefault: vi.fn() };
    listener(event, "https://evil.example/");
    expect(event.preventDefault).toHaveBeenCalled();
  });

  it("allows navigation to the currently loaded URL (same-page reloads)", () => {
    captured = null;
    createWindow();
    const onFn = captured!.webContents.on;
    const willNavigateCall = onFn.mock.calls.find(
      (c: unknown[]) => c[0] === "will-navigate",
    );
    const listener = willNavigateCall![1] as (
      event: { preventDefault: () => void },
      url: string,
    ) => void;
    const event = { preventDefault: vi.fn() };
    // getURL() was mocked to return this value.
    listener(event, "file:///renderer/index.html");
    expect(event.preventDefault).not.toHaveBeenCalled();
  });
});
