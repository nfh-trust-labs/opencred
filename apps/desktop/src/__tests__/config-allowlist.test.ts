/**
 * Tests for the GET_CONFIG/SET_CONFIG handler allowlist (#331).
 *
 * These verify that handleGetConfig and handleSetConfig refuse to touch
 * keys outside the closed set, protecting sensitive blobs like
 * `preferences.dediCredentialEncrypted` and `preferences.importedKeyPaths`
 * from renderer-side read/write.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import * as os from "node:os";

// -----------------------------------------------------------------------
// Electron + store mocks — must run before importing ipc-handlers
// -----------------------------------------------------------------------

const registeredHandlers: Record<string, (...args: unknown[]) => unknown> = {};

vi.mock("electron", () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => unknown) => {
      registeredHandlers[channel] = handler;
    }),
    removeHandler: vi.fn(),
  },
  app: {
    getPath: vi.fn((name: string) => {
      if (name === "userData") return os.tmpdir();
      if (name === "logs") return os.tmpdir();
      return os.tmpdir();
    }),
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
  bugReportFormUrl: "https://forms.gle/test",
  keyRotationDismissedUntil: undefined,
  organizationName: undefined,
  preferences: { dediCredentialEncrypted: "SECRET_ENCRYPTED_BLOB", importedKeyPaths: {} },
  customSchemas: [],
  dediConfig: undefined,
};

vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => ({
    get: vi.fn((key: string) => storeData[key]),
    set: vi.fn((key: string, value: unknown) => {
      storeData[key] = value;
    }),
    store: {},
    path: "/tmp/test-store",
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

describe("Config allowlist (#331)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("handleGetConfig", () => {
    it("allows reading bugReportFormUrl", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.GET_CONFIG];
      const result = await handler(fakeEvent, { key: "bugReportFormUrl" });
      expect(result).toBe("https://forms.gle/test");
    });

    it("allows reading organizationName", async () => {
      storeData.organizationName = "Acme Corp";
      const handler = registeredHandlers[IPC_CHANNELS.GET_CONFIG];
      const result = await handler(fakeEvent, { key: "organizationName" });
      expect(result).toBe("Acme Corp");
    });

    it("allows reading keyRotationDismissedUntil", async () => {
      storeData.keyRotationDismissedUntil = "2026-12-31T00:00:00.000Z";
      const handler = registeredHandlers[IPC_CHANNELS.GET_CONFIG];
      const result = await handler(fakeEvent, { key: "keyRotationDismissedUntil" });
      expect(result).toBe("2026-12-31T00:00:00.000Z");
    });

    it("BLOCKS reading preferences (contains encrypted DeDi credential)", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.GET_CONFIG];
      const result = await handler(fakeEvent, { key: "preferences" });
      expect(result).toBeUndefined();
    });

    it("BLOCKS reading dediConfig", async () => {
      storeData.dediConfig = { baseUrl: "https://api.example", namespace: "ns" };
      const handler = registeredHandlers[IPC_CHANNELS.GET_CONFIG];
      const result = await handler(fakeEvent, { key: "dediConfig" });
      expect(result).toBeUndefined();
    });

    it("BLOCKS reading customSchemas", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.GET_CONFIG];
      const result = await handler(fakeEvent, { key: "customSchemas" });
      expect(result).toBeUndefined();
    });

    it("BLOCKS reading arbitrary unknown keys", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.GET_CONFIG];
      const result = await handler(fakeEvent, { key: "some.nested.key" });
      expect(result).toBeUndefined();
    });
  });

  describe("handleSetConfig", () => {
    it("allows writing organizationName", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.SET_CONFIG];
      await handler(fakeEvent, { key: "organizationName", value: "NewName" });
      expect(storeData.organizationName).toBe("NewName");
    });

    it("allows writing keyRotationDismissedUntil", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.SET_CONFIG];
      await handler(fakeEvent, { key: "keyRotationDismissedUntil", value: "2026-01-01" });
      expect(storeData.keyRotationDismissedUntil).toBe("2026-01-01");
    });

    it("BLOCKS writing bugReportFormUrl (read-only)", async () => {
      const before = storeData.bugReportFormUrl;
      const handler = registeredHandlers[IPC_CHANNELS.SET_CONFIG];
      await handler(fakeEvent, { key: "bugReportFormUrl", value: "https://evil.example" });
      expect(storeData.bugReportFormUrl).toBe(before);
    });

    it("BLOCKS writing preferences (renderer cannot clobber importedKeyPaths)", async () => {
      const before = storeData.preferences;
      const handler = registeredHandlers[IPC_CHANNELS.SET_CONFIG];
      await handler(fakeEvent, {
        key: "preferences",
        value: { importedKeyPaths: { attackerKey: { path: "/tmp/evil.pem" } } },
      });
      expect(storeData.preferences).toBe(before);
    });

    it("BLOCKS writing dediConfig", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.SET_CONFIG];
      await handler(fakeEvent, {
        key: "dediConfig",
        value: { baseUrl: "https://evil.example", namespace: "x" },
      });
      expect(storeData.dediConfig).not.toEqual({ baseUrl: "https://evil.example", namespace: "x" });
    });

    it("BLOCKS writing customSchemas", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.SET_CONFIG];
      await handler(fakeEvent, { key: "customSchemas", value: [{ id: "evil" }] });
      expect(storeData.customSchemas).toEqual([]);
    });

    it("BLOCKS writing arbitrary unknown keys", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.SET_CONFIG];
      await handler(fakeEvent, { key: "arbitrary.key", value: "anything" });
      expect(storeData["arbitrary.key"]).toBeUndefined();
    });
  });
});
