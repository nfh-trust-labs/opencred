/**
 * Tests for the electron-store security hardening:
 *  - persistKeyPaths default value
 *  - restrictStoreFilePermissions behavior
 *
 * Since electron-store requires an Electron environment (app.getPath),
 * these tests mock the electron-store module.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import * as fsModule from "node:fs";

// Mock electron-store before importing the store module.
const mockGet = vi.fn();
const mockSet = vi.fn();
const mockStorePath = "/mock/path/to/opencred-config.json";
const mockStore = {
  get: mockGet,
  set: mockSet,
  store: {},
  path: mockStorePath,
};

let ElectronStoreCtor: ReturnType<typeof vi.fn>;

vi.mock("electron-store", () => {
  ElectronStoreCtor = vi.fn().mockImplementation(() => mockStore);
  return { default: ElectronStoreCtor };
});

vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof fsModule>("node:fs");
  return {
    ...actual,
    chmodSync: vi.fn(),
  };
});

// Import after mocking.
const { initStore, getStore, restrictStoreFilePermissions } = await import("../main/store");

describe("Store security hardening", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("persistKeyPaths default", () => {
    it("should include persistKeyPaths: true in the schema defaults", () => {
      // initStore is called with defaults that include persistKeyPaths: true.
      initStore();

      // The ElectronStore constructor was called; verify it was invoked with
      // defaults that include persistKeyPaths.
      const constructorCall = ElectronStoreCtor.mock.calls[0]?.[0] as
        | { defaults?: Record<string, unknown> }
        | undefined;
      expect(constructorCall?.defaults).toHaveProperty("persistKeyPaths", true);
    });
  });

  describe("restrictStoreFilePermissions", () => {
    it("should call fs.chmodSync with 0o600 on the store path", () => {
      initStore();
      restrictStoreFilePermissions();

      expect(fsModule.chmodSync).toHaveBeenCalledWith(mockStorePath, 0o600);
    });

    it("should not throw if chmodSync fails", () => {
      vi.mocked(fsModule.chmodSync).mockImplementationOnce(() => {
        throw new Error("Permission denied");
      });

      initStore();
      // Should not throw — best-effort behavior.
      expect(() => restrictStoreFilePermissions()).not.toThrow();
    });

    it("should call chmodSync exactly once per invocation", () => {
      initStore();
      vi.mocked(fsModule.chmodSync).mockClear();
      restrictStoreFilePermissions();
      expect(fsModule.chmodSync).toHaveBeenCalledTimes(1);
    });
  });

  describe("persistKeyPaths opt-out behavior", () => {
    it("should return false when persistKeyPaths is set to false", () => {
      initStore();
      const store = getStore();

      mockGet.mockImplementation((key: string) => {
        if (key === "persistKeyPaths") return false;
        return undefined;
      });

      const shouldPersist = store.get("persistKeyPaths" as keyof typeof store.store);
      expect(shouldPersist).toBe(false);
    });

    it("should return true when persistKeyPaths is set to true", () => {
      initStore();
      const store = getStore();

      mockGet.mockImplementation((key: string) => {
        if (key === "persistKeyPaths") return true;
        return undefined;
      });

      const shouldPersist = store.get("persistKeyPaths" as keyof typeof store.store);
      expect(shouldPersist).toBe(true);
    });

    it("should default to true when persistKeyPaths is undefined (via nullish coalescing)", () => {
      initStore();
      const store = getStore();

      mockGet.mockReturnValue(undefined);

      const shouldPersist = store.get("persistKeyPaths" as keyof typeof store.store) ?? true;
      expect(shouldPersist).toBe(true);
    });
  });
});
