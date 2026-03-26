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

  it("removes stale entries when files are missing", () => {
    mockCreateSoftwareSigner.mockImplementation(() => {
      throw new Error("ENOENT: no such file");
    });

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

    expect(store.set).toHaveBeenCalledWith(
      "preferences",
      expect.objectContaining({
        importedKeyPaths: {},
        otherPref: "keep",
      }),
    );
  });

  it("handles mixed valid and stale entries", () => {
    const validSigner = makeMockSigner("did:key:valid");

    mockCreateSoftwareSigner.mockImplementation((filePath: string) => {
      if (filePath === "/signing/valid.pem") {
        return { signer: validSigner, format: "pem" };
      }
      throw new Error("ENOENT");
    });

    const store = makeStore({
      persistKeyPaths: true,
      preferences: {
        importedKeyPaths: {
          "did:key:valid": { path: "/signing/valid.pem", label: "Valid" },
          "did:key:stale": { path: "/signing/stale.pem", label: "Stale" },
        },
      },
    });

    const result = reloadPersistedSigners(store);

    expect(mockCreateSoftwareSigner).toHaveBeenCalledTimes(2);
    expect(result.metadata.size).toBe(1);
    expect(result.metadata.has("did:key:valid")).toBe(true);

    // Stale entry cleaned up
    expect(store.set).toHaveBeenCalledWith(
      "preferences",
      expect.objectContaining({
        importedKeyPaths: {
          "did:key:valid": { path: "/signing/valid.pem", label: "Valid" },
        },
      }),
    );
  });

  it("does not crash on corrupt store data", () => {
    const store = {
      get: vi.fn(() => { throw new Error("Store corrupted"); }),
      set: vi.fn(),
    };

    expect(() => reloadPersistedSigners(store)).not.toThrow();
  });
});
