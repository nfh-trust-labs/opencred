/**
 * Tests for reloadPersistedKeys() — auto-reload of signing keys on startup.
 *
 * Mocks electron, electron-store, and the software-signer to test the
 * reload logic in isolation from Electron and filesystem dependencies.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Hoisted mocks — vi.hoisted ensures these are available in vi.mock factories
// ---------------------------------------------------------------------------

const { mockCreateSoftwareSigner, mockStoreData, mockStoreInstance } = vi.hoisted(() => {
  const mockStoreData: Record<string, unknown> = {};
  const mockStoreInstance = {
    get: vi.fn((key: string) => mockStoreData[key]),
    set: vi.fn((key: string, value: unknown) => {
      mockStoreData[key] = value;
    }),
    path: "/mock/store/config.json",
    store: {},
  };
  return {
    mockCreateSoftwareSigner: vi.fn(),
    mockStoreData,
    mockStoreInstance,
  };
});

// ---------------------------------------------------------------------------
// Mocks — must be declared before imports
// ---------------------------------------------------------------------------

// Mock electron (ipcMain is used by ipc-handlers.ts at module level)
vi.mock("electron", () => ({
  ipcMain: {
    handle: vi.fn(),
    removeHandler: vi.fn(),
  },
  dialog: {
    showOpenDialog: vi.fn(),
    showSaveDialog: vi.fn(),
  },
}));

// Mock electron-store (used by store.ts)
vi.mock("electron-store", () => ({
  default: vi.fn(() => mockStoreInstance),
}));

// Mock the software signer — path relative to test file
vi.mock("../signing/software-signer.js", () => ({
  createSoftwareSigner: mockCreateSoftwareSigner,
  buildSigner: vi.fn(),
}));

// Mock local-signing-flow
vi.mock("../signing/local-signing-flow.js", () => ({
  buildAndSign: vi.fn(),
  listSchemas: vi.fn(),
  getSchemaDefinition: vi.fn(),
}));

// Mock proof-format-router
vi.mock("../signing/proof-format-router.js", () => ({
  signWithFormat: vi.fn(),
}));

// Mock packager
vi.mock("../packaging/packager.js", () => ({
  packageCredential: vi.fn(),
}));

// Mock json-export
vi.mock("../packaging/json-export.js", () => ({
  parseCredentialJson: vi.fn(),
}));

// Mock credential-export
vi.mock("../main/credential-export.js", () => ({
  packageCredential: vi.fn(),
}));

// Mock revocation-queue
vi.mock("../main/revocation-queue.js", () => ({
  queueRevocation: vi.fn(),
  getQueueItems: vi.fn(),
  publishPendingRevocations: vi.fn(),
}));

// Mock attestation-store
vi.mock("../main/attestation-store.js", () => ({
  storeAttestation: vi.fn(),
  getAttestation: vi.fn(),
  listAttestations: vi.fn(),
  removeAttestation: vi.fn(),
  hasAttestation: vi.fn(),
}));

// Mock auto-updater
vi.mock("../main/auto-updater.js", () => ({
  checkForUpdates: vi.fn(),
  downloadUpdate: vi.fn(),
  quitAndInstall: vi.fn(),
  getUpdateStatus: vi.fn(),
}));

// Mock batch modules
vi.mock("../batch/csv-parser.js", () => ({
  parseCsv: vi.fn(),
}));
vi.mock("../batch/batch-engine.js", () => ({
  createBatchEngine: vi.fn(),
}));
vi.mock("../batch/batch-export.js", () => ({
  exportBatchAsZip: vi.fn(),
}));

// Mock store module
vi.mock("../main/store.js", () => ({
  getStore: vi.fn(() => mockStoreInstance),
  restrictStoreFilePermissions: vi.fn(),
  CREDENTIAL_HISTORY_CAP: 100,
}));

// Mock @opencred/* packages that ipc-handlers.ts imports
vi.mock("@opencred/crypto", () => ({
  verifyProof: vi.fn(),
}));

vi.mock("@opencred/shared", () => ({
  CryptoError: class CryptoError extends Error {},
  ValidationError: class ValidationError extends Error {},
  SchemaValidationError: class SchemaValidationError extends Error {},
}));

vi.mock("node:fs/promises", () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  stat: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Import the function under test (after mocks are set up)
// ---------------------------------------------------------------------------

import { reloadPersistedKeys } from "../main/ipc-handlers.js";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("reloadPersistedKeys", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset mock store data
    for (const key of Object.keys(mockStoreData)) {
      delete mockStoreData[key];
    }
    // Restore default get implementation after clearAllMocks
    mockStoreInstance.get.mockImplementation((key: string) => mockStoreData[key]);
  });

  it("should skip reload when persistKeyPaths is false", () => {
    mockStoreData["persistKeyPaths"] = false;

    reloadPersistedKeys();

    expect(mockCreateSoftwareSigner).not.toHaveBeenCalled();
  });

  it("should skip reload when no saved paths exist", () => {
    mockStoreData["persistKeyPaths"] = true;
    mockStoreData["preferences"] = {};

    reloadPersistedKeys();

    expect(mockCreateSoftwareSigner).not.toHaveBeenCalled();
  });

  it("should load keys from persisted paths (legacy string format)", () => {
    mockStoreData["persistKeyPaths"] = true;
    mockStoreData["preferences"] = {
      importedKeyPaths: {
        "did:key:z6MkTest1": "/mock/fixtures/test-keyfile-1",
      },
    };

    const mockSigner = {
      id: "did:key:z6MkTest1",
      metadata: { fingerprint: "z6MkTest1fp" },
      sign: vi.fn(),
    };
    mockCreateSoftwareSigner.mockReturnValue({
      signer: mockSigner,
      format: "pem",
    });

    reloadPersistedKeys();

    expect(mockCreateSoftwareSigner).toHaveBeenCalledWith("/mock/fixtures/test-keyfile-1", undefined);
  });

  it("should restore label from persisted key entry", () => {
    mockStoreData["persistKeyPaths"] = true;
    mockStoreData["preferences"] = {
      importedKeyPaths: {
        "did:key:z6MkTest1": { path: "/mock/fixtures/test-keyfile-1", label: "My DSC Key" },
      },
    };

    const mockSigner = {
      id: "did:key:z6MkTest1",
      metadata: { fingerprint: "z6MkTest1fp" },
      sign: vi.fn(),
    };
    mockCreateSoftwareSigner.mockReturnValue({
      signer: mockSigner,
      format: "pem",
    });

    reloadPersistedKeys();

    expect(mockCreateSoftwareSigner).toHaveBeenCalledWith("/mock/fixtures/test-keyfile-1", "My DSC Key");
  });

  it("should remove stale paths when key file is missing", () => {
    mockStoreData["persistKeyPaths"] = true;
    mockStoreData["preferences"] = {
      importedKeyPaths: {
        "did:key:z6MkStale": { path: "/mock/fixtures/missing-keyfile", label: "Gone" },
        "did:key:z6MkValid": { path: "/mock/fixtures/valid-keyfile", label: "Good" },
      },
    };

    const mockSigner = {
      id: "did:key:z6MkValid",
      metadata: { fingerprint: "z6MkValidFp" },
      sign: vi.fn(),
    };

    mockCreateSoftwareSigner
      .mockImplementationOnce(() => {
        throw new Error("Failed to read key file");
      })
      .mockReturnValueOnce({ signer: mockSigner, format: "pem" });

    reloadPersistedKeys();

    // Store should be updated to remove the stale path
    expect(mockStoreInstance.set).toHaveBeenCalledWith("preferences", {
      importedKeyPaths: {
        "did:key:z6MkValid": { path: "/mock/fixtures/valid-keyfile", label: "Good" },
      },
    });
  });

  it("should warn when lastKeyId was not loaded", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    mockStoreData["persistKeyPaths"] = true;
    mockStoreData["preferences"] = {
      importedKeyPaths: {
        "did:key:z6MkLoaded": "/mock/fixtures/loaded-keyfile",
      },
    };
    mockStoreData["lastKeyId"] = "did:key:z6MkMissing";

    const mockSigner = {
      id: "did:key:z6MkLoaded",
      metadata: { fingerprint: "z6MkLoadedFp" },
      sign: vi.fn(),
    };
    mockCreateSoftwareSigner.mockReturnValue({
      signer: mockSigner,
      format: "pem",
    });

    reloadPersistedKeys();

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("lastKeyId=did:key:z6MkMissing was not loaded"),
    );

    warnSpy.mockRestore();
  });

  it("should not crash when store throws an error", () => {
    mockStoreInstance.get.mockImplementationOnce(() => {
      throw new Error("Store corrupted");
    });

    // Should not throw
    expect(() => reloadPersistedKeys()).not.toThrow();
  });

  it("should load multiple keys with labels", () => {
    mockStoreData["persistKeyPaths"] = true;
    mockStoreData["preferences"] = {
      importedKeyPaths: {
        "did:key:z6MkFirst": { path: "/mock/fixtures/keyfile-1", label: "Key One" },
        "did:key:z6MkSecond": { path: "/mock/fixtures/keyfile-2", label: "Key Two" },
      },
    };

    mockCreateSoftwareSigner
      .mockReturnValueOnce({
        signer: { id: "did:key:z6MkFirst", metadata: { fingerprint: "fp1" }, sign: vi.fn() },
        format: "pem",
      })
      .mockReturnValueOnce({
        signer: { id: "did:key:z6MkSecond", metadata: { fingerprint: "fp2" }, sign: vi.fn() },
        format: "jwk",
      });

    reloadPersistedKeys();

    expect(mockCreateSoftwareSigner).toHaveBeenCalledTimes(2);
    expect(mockCreateSoftwareSigner).toHaveBeenCalledWith("/mock/fixtures/keyfile-1", "Key One");
    expect(mockCreateSoftwareSigner).toHaveBeenCalledWith("/mock/fixtures/keyfile-2", "Key Two");
  });
});
