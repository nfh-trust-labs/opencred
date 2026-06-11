/**
 * Tests for reloadPersistedSigners — auto-reload of signing identities on startup.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock("electron-log", () => {
  const scopedLogger = {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  };
  return {
    default: {
      ...scopedLogger,
      scope: () => scopedLogger,
      transports: {
        file: { maxSize: 0, format: "", getFile: () => ({ path: "/tmp/test.log" }) },
        console: { format: "" },
      },
      hooks: { push: vi.fn() },
      initialize: vi.fn(),
    },
  };
});

const mockCreateSoftwareSigner = vi.fn();

vi.mock("@opencred/signing/software-signer", () => ({
  createSoftwareSigner: (...args: unknown[]) => mockCreateSoftwareSigner(...args),
}));

// Default: treat every path as existing. Individual tests override via
// mockExistsSync.mockImplementation(...).
const mockExistsSync = vi.fn(() => true);
vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    existsSync: (p: string) => mockExistsSync(p),
  };
});

// Import after all mocks
const { reloadPersistedSigners } = await import("../main/persisted-signer-loader.js");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMockSigner(id: string, fingerprint = "abc123") {
  return {
    id,
    metadata: { fingerprint, label: "test" },
    algorithm: "ECDSA P-256",
    sign: vi.fn(),
    type: "software",
  };
}

function makeStore(data: Record<string, unknown> = {}) {
  return {
    get: vi.fn((key: string) => data[key]),
    set: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("reloadPersistedSigners", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockExistsSync.mockReturnValue(true);
  });

  it("skips reload when persistence is disabled", () => {
    const store = makeStore({ persistKeyPaths: false });

    const result = reloadPersistedSigners(store);

    expect(result.metadata.size).toBe(0);
    expect(result.signers.size).toBe(0);
    expect(mockCreateSoftwareSigner).not.toHaveBeenCalled();
  });

  it("skips reload when no persisted entries exist", () => {
    const store = makeStore({ persistKeyPaths: true, preferences: {} });

    const result = reloadPersistedSigners(store);

    expect(result.metadata.size).toBe(0);
    expect(mockCreateSoftwareSigner).not.toHaveBeenCalled();
  });

  it("reloads signers from persisted paths with labels", () => {
    const signer = makeMockSigner("did:key:z123");
    mockCreateSoftwareSigner.mockReturnValue({ signer, format: "pem" });

    const store = makeStore({
      persistKeyPaths: true,
      preferences: {
        importedKeyPaths: {
          "did:key:z123": { path: "/signing/my-cert.pem", label: "My Cert" },
        },
      },
    });

    const result = reloadPersistedSigners(store);

    expect(mockCreateSoftwareSigner).toHaveBeenCalledWith("/signing/my-cert.pem", "My Cert");
    expect(result.metadata.size).toBe(1);
    expect(result.signers.size).toBe(1);
    expect(result.metadata.get("did:key:z123")?.label).toBe("My Cert");
    expect(result.metadata.get("did:key:z123")?.source).toBe("file");
  });

  it("supports legacy string format (backward compatibility)", () => {
    const signer = makeMockSigner("did:key:z456");
    mockCreateSoftwareSigner.mockReturnValue({ signer, format: "pem" });

    const store = makeStore({
      persistKeyPaths: true,
      preferences: {
        importedKeyPaths: {
          "did:key:z456": "/signing/legacy.pem",
        },
      },
    });

    const result = reloadPersistedSigners(store);

    expect(mockCreateSoftwareSigner).toHaveBeenCalledWith("/signing/legacy.pem", undefined);
    expect(result.metadata.size).toBe(1);
  });

  it("removes entries when the key file is missing (ENOENT)", () => {
    mockExistsSync.mockReturnValue(false);

    const store = makeStore({
      persistKeyPaths: true,
      preferences: {
        importedKeyPaths: {
          "did:key:gone": { path: "/signing/deleted.pem", label: "Gone" },
        },
        otherPref: "keep",
      },
    });

    reloadPersistedSigners(store);

    expect(mockCreateSoftwareSigner).not.toHaveBeenCalled();
    expect(store.set).toHaveBeenCalledWith(
      "preferences",
      expect.objectContaining({
        importedKeyPaths: {},
        otherPref: "keep",
      }),
    );
  });

  it("keeps entries when the file exists but loading fails (transient error)", () => {
    // Simulates a permission-denied / locked-by-another-process / corrupt
    // file case. The entry MUST be kept so the user can retry next launch.
    mockExistsSync.mockReturnValue(true);
    mockCreateSoftwareSigner.mockImplementation(() => {
      throw new Error("Failed to read key file");
    });

    const store = makeStore({
      persistKeyPaths: true,
      preferences: {
        importedKeyPaths: {
          "did:key:locked": { path: "/signing/locked.pem", label: "Locked" },
        },
      },
    });

    const result = reloadPersistedSigners(store);

    expect(result.metadata.size).toBe(0);
    expect(result.signers.size).toBe(0);
    // Crucially — store.set must NOT have been called with a cleaned map.
    expect(store.set).not.toHaveBeenCalled();
  });

  it("handles mixed present-but-failing, present-and-ok, and missing entries", () => {
    const validSigner = makeMockSigner("did:key:valid");

    mockExistsSync.mockImplementation((p: string) => p !== "/signing/gone.pem");
    mockCreateSoftwareSigner.mockImplementation((filePath: string) => {
      if (filePath === "/signing/valid.pem") {
        return { signer: validSigner, format: "pem" };
      }
      if (filePath === "/signing/locked.pem") {
        throw new Error("EACCES: permission denied");
      }
      throw new Error("unexpected path");
    });

    const store = makeStore({
      persistKeyPaths: true,
      preferences: {
        importedKeyPaths: {
          "did:key:valid": { path: "/signing/valid.pem", label: "Valid" },
          "did:key:gone": { path: "/signing/gone.pem", label: "Gone" }, // file missing
          "did:key:locked": { path: "/signing/locked.pem", label: "Locked" }, // exists + fails
        },
      },
    });

    const result = reloadPersistedSigners(store);

    // Only the valid entry loaded
    expect(result.metadata.size).toBe(1);
    expect(result.metadata.has("did:key:valid")).toBe(true);

    // Gone entry removed, locked entry KEPT.
    expect(store.set).toHaveBeenCalledWith(
      "preferences",
      expect.objectContaining({
        importedKeyPaths: {
          "did:key:valid": { path: "/signing/valid.pem", label: "Valid" },
          "did:key:locked": { path: "/signing/locked.pem", label: "Locked" },
        },
      }),
    );
  });

  it("does not crash on corrupt store data", () => {
    const store = {
      get: vi.fn(() => {
        throw new Error("Store corrupted");
      }),
      set: vi.fn(),
    };

    expect(() => reloadPersistedSigners(store)).not.toThrow();
  });
});
