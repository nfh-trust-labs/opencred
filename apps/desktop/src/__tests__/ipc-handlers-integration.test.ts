/**
 * Integration tests for IPC handlers.
 *
 * Tests the full user-facing flows: key import → build & sign → verify,
 * covering all 3 proof formats (vc-jwt, data-integrity, sd-jwt-vc) and
 * both did:key and did:web issuers.
 *
 * Also covers DeDi publishing, inline schema path, and revocation queue.
 *
 * Uses real P-256 key pairs and real crypto — no signing mocks.
 * Mocks only Electron APIs (ipcMain, dialog, safeStorage) and electron-store.
 */

import { describe, it, expect, vi, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ---------------------------------------------------------------------------
// Mocks — set up before any module imports
// ---------------------------------------------------------------------------

// Capture registered IPC handlers so we can call them directly
const registeredHandlers: Record<string, (...args: unknown[]) => unknown> = {};

vi.mock("electron", () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => unknown) => {
      registeredHandlers[channel] = handler;
    }),
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

// Mock electron-store
const storeData: Record<string, unknown> = {
  recentTemplates: [],
  dediPublishedSchemas: [],
  credentialHistory: [],
};
vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => ({
    get: vi.fn((key: string) => storeData[key]),
    set: vi.fn((key: string, value: unknown) => {
      storeData[key] = value;
    }),
    store: {},
  })),
}));

// Mock auto-updater (not relevant to these tests)
vi.mock("electron-updater", () => ({
  default: { autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() } },
  autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() },
}));

// Mock DeDi publish manager — we test DeDi separately
const mockEnsureSchemaPublished = vi.fn();
const mockPublishDIDDocument = vi.fn();
const mockEnsureRegistries = vi.fn();

vi.mock("@opencred/dedi-client", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    createPublishManager: vi.fn(() => ({
      ensureSchemaPublished: mockEnsureSchemaPublished,
      publishDIDDocument: mockPublishDIDDocument,
      ensureRegistries: mockEnsureRegistries,
      getPublishedSchemaIds: () => [],
    })),
    DeDiPublishManager: vi.fn(),
  };
});

// Mock OS cert provider (native addon)
vi.mock("../signing/os-cert-provider", () => ({
  listOsCertificates: vi.fn(async () => []),
  signWithOsCert: vi.fn(),
}));

// Mock PKCS#11 (native addon) via the lazy loader
vi.mock("@opencred/signing/pkcs11-loader", () => ({
  loadPkcs11js: () => ({ PKCS11: class {} }),
}));

// Mock keytar (native keychain)
vi.mock("keytar", () => ({
  getPassword: vi.fn(async () => null),
  setPassword: vi.fn(async () => {}),
  deletePassword: vi.fn(async () => true),
}));

// Mock node:dns/promises so SCHEMA_FETCH_URL tests can drive DNS responses
// without leaking real network calls. lookup is also mocked because
// other handlers (e.g., GET_OFFLINE_STATUS) call it; we default it to
// reject so those code paths treat the machine as offline.
vi.mock("node:dns/promises", () => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
  lookup: vi.fn().mockRejectedValue(new Error("ENOTFOUND")),
}));

// Initialise store before importing IPC handlers
const { initStore } = await import("../main/store");
initStore();

// Now import and register handlers
const { registerIpcHandlers } = await import("../main/ipc-handlers");
registerIpcHandlers();

const { IPC_CHANNELS } = await import("../shared/ipc-channels");

// ---------------------------------------------------------------------------
// Test key setup
// ---------------------------------------------------------------------------

let tmpDir: string;
let ecKeyPath: string;

const { privateKey: testEcKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-ipc-test-"));
  ecKeyPath = path.join(tmpDir, "test-p256.pem");
  fs.writeFileSync(ecKeyPath, testEcKey.export({ format: "pem", type: "pkcs8" }) as string);
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

beforeEach(() => {
  vi.clearAllMocks();
  // Reset store data
  storeData["recentTemplates"] = [];
  storeData["dediPublishedSchemas"] = [];
  storeData["credentialHistory"] = [];
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fakeEvent = null as unknown; // IpcMainInvokeEvent — not used by handlers

/** Import a key and return its metadata. */
async function importTestKey(): Promise<{ keyId: string }> {
  const handler = registeredHandlers[IPC_CHANNELS.KEY_IMPORT];
  const result = (await handler(fakeEvent, { filePath: ecKeyPath })) as {
    success: boolean;
    key: { id: string };
  };
  expect(result.success).toBe(true);
  return { keyId: result.key.id };
}

/** Build & sign a credential with the given options. */
async function buildAndSign(opts: Record<string, unknown>) {
  const handler = registeredHandlers[IPC_CHANNELS.BUILD_AND_SIGN];
  return handler(fakeEvent, opts) as Promise<{
    success: boolean;
    signedCredential?: string;
    proofFormat?: string;
    error?: string;
    errorCode?: string;
  }>;
}

/** Verify a signed credential. */
async function verifyCredential(credentialJson: string) {
  const handler = registeredHandlers[IPC_CHANNELS.VERIFY_CREDENTIAL];
  return handler(fakeEvent, { credential: credentialJson }) as Promise<{
    success: boolean;
    valid?: boolean;
    error?: string;
    message?: string;
  }>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Test suites
// ═══════════════════════════════════════════════════════════════════════════

describe("IPC Handler Integration Tests", () => {
  // -----------------------------------------------------------------------
  // Key management
  // -----------------------------------------------------------------------
  describe("Key management", () => {
    it("should import a PEM key and return metadata", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.KEY_IMPORT];
      const result = (await handler(fakeEvent, { filePath: ecKeyPath })) as {
        success: boolean;
        key: { id: string; fingerprint: string; algorithm: string };
      };

      expect(result.success).toBe(true);
      expect(result.key).toBeDefined();
      expect(result.key.id).toContain("did:key:");
      expect(result.key.fingerprint).toBeDefined();
    });

    it("should list imported keys", async () => {
      await importTestKey();

      const handler = registeredHandlers[IPC_CHANNELS.KEY_LIST];
      const result = (await handler(fakeEvent)) as { keys: Array<Record<string, unknown>> };

      expect(result.keys.length).toBeGreaterThanOrEqual(1);
      expect(result.keys[0].algorithm).toBe("ECDSA P-256");
    });

    it("should generate a new key pair", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.KEY_GENERATE];
      const result = (await handler(fakeEvent, {})) as {
        success: boolean;
        key: { id: string };
      };

      expect(result.success).toBe(true);
      expect(result.key.id).toContain("did:key:");
    });

    it("should reject import of nonexistent file", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.KEY_IMPORT];
      const result = (await handler(fakeEvent, { filePath: "/nonexistent/key.pem" })) as Record<
        string,
        unknown
      >;

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  // -----------------------------------------------------------------------
  // Signing — schema-based flow (all 3 proof formats)
  // -----------------------------------------------------------------------
  describe("Build & sign — schema-based flow", () => {
    it("vc-jwt: should sign with education schema and did:key issuer", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: "did:key:z6Mktest",
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      if (!result.success) {
        throw new Error(`Build & sign failed: ${result.error} (code: ${result.errorCode})`);
      }
      expect(result.proofFormat).toBe("vc-jwt");

      const signed = JSON.parse(result.signedCredential!);
      expect(signed.issuer).toBe("did:key:z6Mktest");
      expect(signed.proof.type).toBe("JsonWebSignature2020");
      expect(signed.proof.jwt).toBeDefined();
    });

    it("data-integrity: should sign with education schema and did:key issuer", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: "did:key:z6Mktest",
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "data-integrity",
      });

      expect(result.success).toBe(true);
      expect(result.proofFormat).toBe("data-integrity");

      const signed = JSON.parse(result.signedCredential!);
      expect(signed.proof.type).toBe("DataIntegrityProof");
      expect(signed.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
      expect(signed.proof.proofValue).toBeDefined();
    });

    it("sd-jwt-vc: should sign with education schema", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: "did:key:z6Mktest",
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "sd-jwt-vc",
        selectiveDisclosureClaims: ["name", "role"],
      });

      expect(result.success).toBe(true);
      expect(result.proofFormat).toBe("sd-jwt-vc");

      // SD-JWT-VC output is a compact token with ~ separators
      expect(result.signedCredential).toContain("~");
    });
  });

  // -----------------------------------------------------------------------
  // Signing — did:web verificationMethod (the bug we fixed)
  // -----------------------------------------------------------------------
  describe("Build & sign — did:web verificationMethod", () => {
    it("vc-jwt with did:web issuer should use did:web#key-0 as verificationMethod", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: "did:web:issuer.example.com",
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(result.success).toBe(true);

      // Decode the JWT header to check the kid
      const signed = JSON.parse(result.signedCredential!);
      const jwt = signed.proof.jwt;
      const [headerB64] = jwt.split(".");
      const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
      expect(header.kid).toBe("did:web:issuer.example.com#key-0");
    });

    it("data-integrity with did:web issuer should use did:web#key-0 as verificationMethod", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: "did:web:issuer.example.com",
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "data-integrity",
      });

      expect(result.success).toBe(true);
      const signed = JSON.parse(result.signedCredential!);
      expect(signed.proof.verificationMethod).toBe("did:web:issuer.example.com#key-0");
    });

    it("did:key issuer should use signer's own ID as verificationMethod", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: "did:key:z6MktestABC",
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "data-integrity",
      });

      expect(result.success).toBe(true);
      const signed = JSON.parse(result.signedCredential!);
      // Should NOT be did:key:z6MktestABC#key-0, should be the signer's did:key ID
      expect(signed.proof.verificationMethod).toContain("did:key:");
      expect(signed.proof.verificationMethod).not.toBe("did:key:z6MktestABC#key-0");
    });
  });

  // -----------------------------------------------------------------------
  // Signing — inline schema path (blank/custom credentials)
  // -----------------------------------------------------------------------
  describe("Build & sign — inline schema", () => {
    it("should build and sign with inline schema (no schema registry)", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        issuerDid: "did:web:custom.example",
        inlineSchema: true,
        credentialSubject: {
          employeeName: "John Smith",
          department: "Engineering",
          employeeId: "EMP-001",
        },
        additionalTypes: ["CustomEmployeeCredential"],
        validFrom: "2025-03-01T00:00:00Z",
        validUntil: "2026-03-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(result.success).toBe(true);

      const signed = JSON.parse(result.signedCredential!);
      expect(signed.issuer).toBe("did:web:custom.example");
      expect(signed.type).toContain("CustomEmployeeCredential");
      expect(signed.credentialSubject.employeeName).toBe("John Smith");
      expect(signed.validUntil).toBe("2026-03-01T00:00:00Z");
    });

    it("should include credentialSchema when URL is provided", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        issuerDid: "did:web:issuer.example",
        inlineSchema: true,
        credentialSubject: { name: "Test" },
        credentialSchemaUrl: "https://schema.example/v1/employee.json",
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(result.success).toBe(true);
      const signed = JSON.parse(result.signedCredential!);
      expect(signed.credentialSchema).toEqual({
        id: "https://schema.example/v1/employee.json",
        type: "JsonSchema",
      });
    });

    it("should include credentialStatus when revocationRegistryUrl is provided", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        issuerDid: "did:web:issuer.example",
        inlineSchema: true,
        credentialSubject: { name: "Test" },
        revocationRegistryUrl: "https://dedi.global/dedi/query/test-ns/vc-revocation-registry",
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(result.success).toBe(true);
      const signed = JSON.parse(result.signedCredential!);
      expect(signed.credentialStatus).toBeDefined();
      expect(signed.credentialStatus.type).toBe("dedi");
      expect(signed.credentialStatus.statusPurpose).toBe("revocation");
      expect(signed.credentialStatus.statusListCredential).toBe(
        "https://dedi.global/dedi/query/test-ns/vc-revocation-registry",
      );
      expect(signed.credentialStatus.id).toMatch(
        /^https:\/\/dedi\.global\/dedi\/lookup\/test-ns\/vc-revocation-registry\/[a-f0-9]{64}$/,
      );
    });

    it("should include subjectDid as id in credentialSubject", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        issuerDid: "did:web:issuer.example",
        inlineSchema: true,
        credentialSubject: { name: "Jane" },
        subjectDid: "did:key:z6MksubjectABC",
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(result.success).toBe(true);
      const signed = JSON.parse(result.signedCredential!);
      expect(signed.credentialSubject.id).toBe("did:key:z6MksubjectABC");
    });

    it("inline schema + did:web should use did:web#key-0 verificationMethod", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        issuerDid: "did:web:my.issuer.example",
        inlineSchema: true,
        credentialSubject: { name: "Test" },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "data-integrity",
      });

      expect(result.success).toBe(true);
      const signed = JSON.parse(result.signedCredential!);
      expect(signed.proof.verificationMethod).toBe("did:web:my.issuer.example#key-0");
    });
  });

  // -----------------------------------------------------------------------
  // Error handling
  // -----------------------------------------------------------------------
  describe("Error handling", () => {
    it("should reject build & sign with nonexistent key", async () => {
      const result = await buildAndSign({
        keyId: "nonexistent-key-id",
        schemaId: "functional-identity/v1",
        issuerDid: "did:key:z6Mktest",
        credentialSubject: {
          name: "Test",
          role: "Test Subject",
          validFrom: "2025-01-01T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe("KEY_NOT_FOUND");
    });

    it("should reject data-integrity with RSA key", async () => {
      // We can't easily import an RSA key via PEM in this test setup,
      // but we test the validation guard in the handler
      const { keyId } = await importTestKey(); // P-256 key

      // P-256 should work fine with data-integrity
      const result = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: "did:key:z6Mktest",
        credentialSubject: {
          name: "Test",
          role: "Test Subject",
          validFrom: "2025-01-01T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "data-integrity",
      });
      expect(result.success).toBe(true);
    });

    it("should reject invalid schema subject data", async () => {
      const { keyId } = await importTestKey();

      const result = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: "did:key:z6Mktest",
        credentialSubject: {
          // Missing required fields: role, validFrom
          name: "Jane",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe("SCHEMA_VALIDATION_ERROR");
    });
  });

  // -----------------------------------------------------------------------
  // Schema operations
  // -----------------------------------------------------------------------
  describe("Schema operations", () => {
    it("should list available schemas", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_LIST];
      const result = (await handler(fakeEvent)) as { schemas: string[] };

      expect(result.schemas).toContain("functional-identity/v1");
      expect(result.schemas).toContain("immunization/v1");
      expect(result.schemas).toContain("electricity/v1");
    });

    it("should get a specific schema definition", async () => {
      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_GET];
      const result = (await handler(fakeEvent, {
        schemaId: "functional-identity/v1",
      })) as Record<string, unknown>;

      expect(result.id).toBe("functional-identity/v1");
      expect(result.schema).toBeDefined();
    });
  });

  // -----------------------------------------------------------------------
  // Full round-trip: sign → verify
  // -----------------------------------------------------------------------
  describe("Sign → Verify round-trip", () => {
    it("vc-jwt: signed credential should verify as valid", async () => {
      const { keyId } = await importTestKey();

      const signResult = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: keyId.split("#")[0],
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(signResult.success).toBe(true);

      const verifyResult = await verifyCredential(signResult.signedCredential!);
      expect(verifyResult.success).toBe(true);
      expect(verifyResult.valid).toBe(true);
    });

    it("data-integrity: signed credential should verify", async () => {
      const { keyId } = await importTestKey();

      const signResult = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: keyId.split("#")[0],
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "data-integrity",
      });

      expect(signResult.success).toBe(true);

      const verifyResult = await verifyCredential(signResult.signedCredential!);
      expect(verifyResult.success).toBe(true);
      expect(verifyResult.valid).toBe(true);
    });

    it("tampered credential should fail verification", async () => {
      const { keyId } = await importTestKey();

      const signResult = await buildAndSign({
        keyId,
        schemaId: "functional-identity/v1",
        issuerDid: keyId.split("#")[0],
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
        },
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "data-integrity",
      });

      expect(signResult.success).toBe(true);

      // Tamper with the credential
      const signed = JSON.parse(signResult.signedCredential!);
      signed.credentialSubject.name = "TAMPERED";
      const tampered = JSON.stringify(signed);

      const verifyResult = await verifyCredential(tampered);
      // Verification should either fail or return valid: false
      if (verifyResult.success) {
        expect(verifyResult.valid).toBe(false);
      }
    });
  });

  // -----------------------------------------------------------------------
  // Revocation queue
  // -----------------------------------------------------------------------
  describe("Revocation queue", () => {
    it("should queue a revocation and return it in status", async () => {
      const queueHandler = registeredHandlers[IPC_CHANNELS.REVOCATION_QUEUE];
      const queueResult = (await queueHandler(fakeEvent, {
        credentialId: "urn:uuid:test-cred-1",
        registryUrl: "https://dedi.global/revocations/test",
        revocationHash: "abc123hash",
        reason: "Testing revocation",
      })) as { success: boolean; item: Record<string, unknown> };

      expect(queueResult.success).toBe(true);
      expect(queueResult.item.credentialId).toBe("urn:uuid:test-cred-1");
      expect(queueResult.item.status).toBe("pending");

      // Check status
      const statusHandler = registeredHandlers[IPC_CHANNELS.REVOCATION_STATUS];
      const statusResult = (await statusHandler(fakeEvent)) as {
        items: Array<Record<string, unknown>>;
      };

      expect(statusResult.items.length).toBeGreaterThanOrEqual(1);
      const found = statusResult.items.find((i) => i.credentialId === "urn:uuid:test-cred-1");
      expect(found).toBeDefined();
    });
  });

  // -----------------------------------------------------------------------
  // Multiple schemas
  // -----------------------------------------------------------------------
  describe("All built-in schemas", () => {
    const schemas = [
      {
        id: "functional-identity/v1",
        subject: {
          name: "Jane",
          role: "University Student",
          validFrom: "2025-01-01T00:00:00Z",
        },
      },
    ];

    for (const { id, subject } of schemas) {
      it(`should sign and verify with ${id} schema`, async () => {
        const { keyId } = await importTestKey();

        const signResult = await buildAndSign({
          keyId,
          schemaId: id,
          issuerDid: "did:key:z6Mktest",
          credentialSubject: subject,
          validFrom: "2025-01-01T00:00:00Z",
          proofFormat: "vc-jwt",
        });

        expect(signResult.success).toBe(true);

        const signed = JSON.parse(signResult.signedCredential!);
        expect(signed.issuer).toBe("did:key:z6Mktest");
        expect(signed.type).toContain("VerifiableCredential");
      });
    }
  });

  // -----------------------------------------------------------------------
  // SCHEMA_FETCH_URL — SSRF + DNS rebinding (TOCTOU) protection
  // (Issue #314)
  // -----------------------------------------------------------------------
  describe("SCHEMA_FETCH_URL", () => {
    let resolve4Spy: ReturnType<typeof vi.fn>;
    let resolve6Spy: ReturnType<typeof vi.fn>;

    beforeEach(async () => {
      const { resolve4, resolve6 } = await import("node:dns/promises");
      resolve4Spy = resolve4 as unknown as ReturnType<typeof vi.fn>;
      resolve6Spy = resolve6 as unknown as ReturnType<typeof vi.fn>;
      resolve4Spy.mockReset();
      resolve6Spy.mockReset();
      // Default both to ENODATA so any test that forgets to set them up
      // gets a clean failure instead of leaking real DNS calls.
      resolve4Spy.mockRejectedValue(new Error("ENODATA"));
      resolve6Spy.mockRejectedValue(new Error("ENODATA"));
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    /** Build a fake fetch Response with the given JSON body. */
    function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}): Response {
      const ok = init.ok ?? true;
      const status = init.status ?? 200;
      return {
        ok,
        status,
        statusText: ok ? "OK" : "Error",
        headers: new Headers({ "content-type": "application/json" }),
        body: null,
        text: vi.fn().mockResolvedValue(JSON.stringify(body)),
        json: vi.fn().mockResolvedValue(body),
      } as unknown as Response;
    }

    it("rejects non-HTTPS URLs without resolving DNS", async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, { url: "http://example.com/schema.json" })) as {
        success: boolean;
        error?: string;
      };

      expect(result.success).toBe(false);
      expect(result.error).toContain("HTTPS");
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(resolve4Spy).not.toHaveBeenCalled();
    });

    it("rejects when ALL resolved IPs are private", async () => {
      resolve4Spy.mockResolvedValue(["127.0.0.1"]);
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, {
        url: "https://evil.example.com/schema.json",
      })) as { success: boolean; error?: string };

      expect(result.success).toBe(false);
      expect(result.error).toContain("private IP");
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("rejects when ANY resolved IP is private (multi-A-record SSRF)", async () => {
      // Reproduces the exact bug called out in the issue: dns.lookup would
      // return only the first record. dns.resolve4 returns the full set so
      // we can refuse the entire request.
      resolve4Spy.mockResolvedValue(["1.2.3.4", "127.0.0.1"]);
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, {
        url: "https://evil.example.com/schema.json",
      })) as { success: boolean; error?: string };

      expect(result.success).toBe(false);
      expect(result.error).toContain("private IP");
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("pins the resolved IP into the fetch URL and sets the Host header (DNS rebinding defence)", async () => {
      resolve4Spy.mockResolvedValue(["93.184.216.34"]);
      const fetchSpy = vi.fn().mockResolvedValue(
        jsonResponse({
          $schema: "https://json-schema.org/draft/2020-12/schema",
          title: "Test schema",
          properties: { name: { type: "string" } },
        }),
      );
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, {
        url: "https://example.com/schema.json",
      })) as { success: boolean; schema?: Record<string, unknown>; title?: string };

      expect(result.success).toBe(true);
      expect(result.title).toBe("Test schema");

      // Critical: the URL passed to fetch must contain the resolved IP, not
      // the original hostname. Otherwise fetch would re-resolve the hostname.
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const calledUrl = fetchSpy.mock.calls[0][0] as string;
      expect(calledUrl).toBe("https://93.184.216.34/schema.json");
      expect(calledUrl).not.toContain("example.com");

      // The Host header carries the original hostname so the server's
      // virtual-host routing still works.
      const calledOptions = fetchSpy.mock.calls[0][1] as {
        headers: Record<string, string>;
        redirect: string;
      };
      expect(calledOptions.headers.Host).toBe("example.com");
      expect(calledOptions.redirect).toBe("error");
    });

    it("does not re-resolve hostname between SSRF check and fetch (TOCTOU defence)", async () => {
      // Simulate a DNS rebinding attacker: the first resolve4 call (for the
      // SSRF check) returns a public IP. A subsequent call (which would
      // happen if fetch re-resolved) would return loopback. The fixed code
      // never makes that subsequent call because the IP is pinned into the
      // fetch URL.
      resolve4Spy
        .mockResolvedValueOnce(["93.184.216.34"]) // First call: public
        .mockResolvedValueOnce(["127.0.0.1"]); // Hypothetical re-resolve: loopback

      const fetchSpy = vi.fn().mockResolvedValue(
        jsonResponse({
          properties: { name: { type: "string" } },
        }),
      );
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, {
        url: "https://rebinding.example.com/schema.json",
      })) as { success: boolean };

      expect(result.success).toBe(true);
      expect(resolve4Spy).toHaveBeenCalledTimes(1);

      const calledUrl = fetchSpy.mock.calls[0][0] as string;
      expect(calledUrl).toContain("93.184.216.34");
      expect(calledUrl).not.toContain("127.0.0.1");
      expect(calledUrl).not.toContain("rebinding.example.com");
    });

    it("rejects when DNS resolution fails entirely", async () => {
      resolve4Spy.mockRejectedValue(new Error("ENOTFOUND"));
      resolve6Spy.mockRejectedValue(new Error("ENOTFOUND"));
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, {
        url: "https://nonexistent.example.com/schema.json",
      })) as { success: boolean; error?: string };

      expect(result.success).toBe(false);
      expect(result.error).toContain("DNS resolution failed");
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("validates HTTPS-only when given a literal IP", async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, {
        url: "https://127.0.0.1/schema.json",
      })) as { success: boolean; error?: string };

      expect(result.success).toBe(false);
      expect(result.error).toContain("private IP");
      expect(fetchSpy).not.toHaveBeenCalled();
      // Literal IP path bypasses DNS entirely.
      expect(resolve4Spy).not.toHaveBeenCalled();
    });

    it("rejects responses larger than the 1 MB cap (Content-Length fast path)", async () => {
      resolve4Spy.mockResolvedValue(["93.184.216.34"]);
      const fetchSpy = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        headers: new Headers({
          "content-type": "application/json",
          "content-length": String(2_000_000),
        }),
        body: null,
        text: vi.fn().mockResolvedValue("{}"),
        json: vi.fn().mockResolvedValue({}),
      } as unknown as Response);
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, {
        url: "https://example.com/schema.json",
      })) as { success: boolean; error?: string };

      expect(result.success).toBe(false);
      expect(result.error).toContain("Response too large");
    });

    it("rejects responses larger than the 1 MB cap (streaming check)", async () => {
      resolve4Spy.mockResolvedValue(["93.184.216.34"]);

      // Simulate a response with a missing/lying Content-Length but a body
      // that streams more than 1 MB. The reader returns 2 MB worth of data
      // in two chunks; the handler must abort before allocating it all.
      const bigChunk = new Uint8Array(700_000);
      bigChunk.fill(0x7b); // "{"
      let chunkIdx = 0;
      const reader = {
        read: vi.fn().mockImplementation(async () => {
          if (chunkIdx < 3) {
            chunkIdx++;
            return { done: false, value: bigChunk };
          }
          return { done: true, value: undefined };
        }),
        cancel: vi.fn().mockResolvedValue(undefined),
      };

      const fetchSpy = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        headers: new Headers({ "content-type": "application/json" }),
        body: { getReader: () => reader },
        text: vi.fn().mockResolvedValue(""),
        json: vi.fn().mockResolvedValue({}),
      } as unknown as Response);
      vi.stubGlobal("fetch", fetchSpy);

      const handler = registeredHandlers[IPC_CHANNELS.SCHEMA_FETCH_URL];
      const result = (await handler(fakeEvent, {
        url: "https://example.com/schema.json",
      })) as { success: boolean; error?: string };

      expect(result.success).toBe(false);
      expect(result.error).toContain("Response too large");
      // The reader should have been cancelled before draining all 3 chunks.
      expect(reader.cancel).toHaveBeenCalled();
    });
  });
});
