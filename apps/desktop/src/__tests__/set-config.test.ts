/**
 * Tests for the `setConfig` IPC handler — focused on per-key validators
 * and the `ALLOWED_CONFIG_KEYS` allowlist.
 *
 * The `bugReportFormUrl` validator gates the renderer's help-menu link:
 * the URL is re-rendered on screen (and potentially clicked by the user),
 * so it must be restricted to https:// and a small set of trusted hosts
 * to prevent phishing / redirect attacks through a tainted config value.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import * as os from "node:os";

// Mirror the mocks from ipc-handlers-integration.test.ts so the handlers
// can be imported and invoked in isolation.

const registeredHandlers: Record<string, (...args: unknown[]) => unknown> = {};

vi.mock("electron", () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => unknown) => {
      registeredHandlers[channel] = handler;
    }),
  },
  app: {
    getPath: vi.fn((_name: string) => os.tmpdir()),
    getVersion: vi.fn(() => "0.1.0-test"),
    getName: vi.fn(() => "opencred-test"),
    isPackaged: false,
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
  BrowserWindow: vi.fn(),
}));

const storeData: Record<string, unknown> = {
  recentTemplates: [],
  dediPublishedSchemas: [],
  credentialHistory: [],
  bugReportFormUrl: "https://forms.gle/f1wFUhzN1VwgR5QD6",
};

vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => ({
    get: vi.fn((key: string) => storeData[key]),
    set: vi.fn((key: string, value: unknown) => {
      storeData[key] = value;
    }),
    store: {},
    path: "/tmp/fake-store.json",
  })),
}));

vi.mock("electron-updater", () => ({
  default: { autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() } },
  autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() },
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

const { initStore } = await import("../main/store");
initStore();

const { registerIpcHandlers } = await import("../main/ipc-handlers");
registerIpcHandlers();

const { IPC_CHANNELS } = await import("../shared/ipc-channels");

const fakeEvent = null as unknown;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("setConfig — bugReportFormUrl validator", () => {
  const setConfig = async (key: string, value: unknown): Promise<void> => {
    const handler = registeredHandlers[IPC_CHANNELS.SET_CONFIG];
    await handler(fakeEvent, { key, value });
  };

  it("rejects an http:// URL (must be https://)", async () => {
    await expect(setConfig("bugReportFormUrl", "http://evil.com")).rejects.toThrow(
      /must use https/i,
    );
  });

  it("rejects an https URL on an untrusted host", async () => {
    await expect(setConfig("bugReportFormUrl", "https://evil.com/x")).rejects.toThrow(
      /host not permitted/i,
    );
  });

  it("rejects a malformed URL", async () => {
    await expect(setConfig("bugReportFormUrl", "not-a-url")).rejects.toThrow(
      /must be a valid URL/i,
    );
  });

  it("rejects a non-string value", async () => {
    await expect(setConfig("bugReportFormUrl", 42)).rejects.toThrow(/must be a string/i);
  });

  it("accepts https://forms.gle/<id>", async () => {
    await setConfig("bugReportFormUrl", "https://forms.gle/abc");
    expect(storeData["bugReportFormUrl"]).toBe("https://forms.gle/abc");
  });

  it("accepts https://docs.google.com/forms/...", async () => {
    await setConfig(
      "bugReportFormUrl",
      "https://docs.google.com/forms/d/e/1FAIpQLScExample/viewform",
    );
    expect(storeData["bugReportFormUrl"]).toMatch(/docs\.google\.com/);
  });

  it("accepts https://sub.github.com/<path> (suffix match)", async () => {
    await setConfig("bugReportFormUrl", "https://sub.github.com/report");
    expect(storeData["bugReportFormUrl"]).toBe("https://sub.github.com/report");
  });

  it("accepts https://github.com/... (exact host match)", async () => {
    await setConfig("bugReportFormUrl", "https://github.com/org/repo/issues/new");
    expect(storeData["bugReportFormUrl"]).toMatch(/^https:\/\/github\.com/);
  });

  it("rejects unknown key with existing allowlist error", async () => {
    await expect(setConfig("notARealKey", "anything")).rejects.toThrow(
      /not accessible via setConfig/,
    );
  });
});
