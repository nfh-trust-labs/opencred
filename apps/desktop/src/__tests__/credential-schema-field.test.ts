/**
 * Tests for the always-on `credentialSchema` field on issued credentials.
 *
 * Per W3C VCDM 2.0 §4.10, every issued credential should reference the
 * JSON Schema it conforms to. The desktop client emits this for every
 * credential, choosing an `id` URL with the priority:
 *
 *   built-in schemas:
 *     1. user-provided `credentialSchemaUrl`
 *     2. the schema's own `$id`
 *
 *   custom (inline) schemas:
 *     1. DeDi schema URL (if published to DeDi)
 *     2. user-provided `credentialSchemaUrl`
 *     3. base64 data URI containing the inline JSON Schema
 */

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ---------------------------------------------------------------------------
// Mocks — must be set up before any module imports
// ---------------------------------------------------------------------------

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
  dialog: { showOpenDialog: vi.fn(), showSaveDialog: vi.fn() },
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
  customSchemas: [],
};
vi.mock("electron-store", () => ({
  default: vi.fn().mockImplementation(() => ({
    get: vi.fn((key: string) => storeData[key]),
    set: vi.fn((key: string, value: unknown) => {
      storeData[key] = value;
    }),
    store: storeData,
  })),
}));

vi.mock("electron-updater", () => ({
  default: { autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() } },
  autoUpdater: { on: vi.fn(), checkForUpdates: vi.fn() },
}));

vi.mock("@opencred/dedi-client", async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    createPublishManager: vi.fn(() => ({
      ensureSchemaPublished: vi.fn(),
      publishDIDDocument: vi.fn(),
      ensureRegistries: vi.fn(),
      publishContext: vi.fn(),
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

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const fakeEvent = null as unknown;

let tmpDir: string;
let ecKeyPath: string;

const { privateKey: testEcKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-cs-test-"));
  ecKeyPath = path.join(tmpDir, "test-p256.pem");
  fs.writeFileSync(ecKeyPath, testEcKey.export({ format: "pem", type: "pkcs8" }) as string);
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

beforeEach(() => {
  storeData["customSchemas"] = [];
  storeData["recentTemplates"] = [];
  storeData["dediPublishedSchemas"] = [];
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function importTestKey(): Promise<{ keyId: string }> {
  const handler = registeredHandlers[IPC_CHANNELS.KEY_IMPORT];
  const result = await handler(fakeEvent, { filePath: ecKeyPath }) as {
    success: boolean;
    key: { id: string };
  };
  expect(result.success).toBe(true);
  return { keyId: result.key.id };
}

async function callBuildAndSign(opts: Record<string, unknown>): Promise<{
  success: boolean;
  signedCredential?: string;
  error?: string;
}> {
  const handler = registeredHandlers[IPC_CHANNELS.BUILD_AND_SIGN];
  return (await handler(fakeEvent, opts)) as {
    success: boolean;
    signedCredential?: string;
    error?: string;
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// Built-in schemas
// ═══════════════════════════════════════════════════════════════════════════

describe("credentialSchema field — built-in schemas", () => {
  it("uses the schema's own $id when no URL is provided", async () => {
    const { keyId } = await importTestKey();

    const result = await callBuildAndSign({
      keyId,
      schemaId: "education",
      issuerDid: "did:key:z6Mktest",
      credentialSubject: {
        name: "Jane",
        degree: "BS",
        institution: "MIT",
        dateConferred: "2025-06-15",
      },
      validFrom: "2025-01-01T00:00:00Z",
      proofFormat: "vc-jwt",
    });

    expect(result.success).toBe(true);
    const signed = JSON.parse(result.signedCredential!);
    expect(signed.credentialSchema).toEqual({
      id: "https://opencred.dev/schemas/education/v1",
      type: "JsonSchema",
    });
  });

  it("a user-provided URL overrides the schema $id", async () => {
    const { keyId } = await importTestKey();

    const result = await callBuildAndSign({
      keyId,
      schemaId: "education",
      issuerDid: "did:key:z6Mktest",
      credentialSubject: {
        name: "Jane",
        degree: "BS",
        institution: "MIT",
        dateConferred: "2025-06-15",
      },
      validFrom: "2025-01-01T00:00:00Z",
      credentialSchemaUrl: "https://issuer.example/schemas/edu-v2.json",
      proofFormat: "vc-jwt",
    });

    expect(result.success).toBe(true);
    const signed = JSON.parse(result.signedCredential!);
    expect(signed.credentialSchema.id).toBe("https://issuer.example/schemas/edu-v2.json");
  });

  it("populates credentialSchema for every built-in schema", async () => {
    const { keyId } = await importTestKey();

    const cases = [
      { id: "education", subject: { name: "X", degree: "BS", institution: "MIT", dateConferred: "2025-01-01" } },
      { id: "employment", subject: { name: "X", employer: "ACME", position: "Eng", startDate: "2025-01-01" } },
      { id: "identity", subject: { name: "X", dateOfBirth: "1990-01-01", nationality: "US", documentNumber: "ABC" } },
      { id: "business", subject: { name: "X", registrationNumber: "1", jurisdiction: "US", incorporationDate: "2000-01-01" } },
    ];

    for (const c of cases) {
      const result = await callBuildAndSign({
        keyId,
        schemaId: c.id,
        issuerDid: "did:key:z6Mktest",
        credentialSubject: c.subject,
        validFrom: "2025-01-01T00:00:00Z",
        proofFormat: "vc-jwt",
      });

      expect(result.success).toBe(true);
      const signed = JSON.parse(result.signedCredential!);
      expect(signed.credentialSchema).toBeDefined();
      expect(signed.credentialSchema.type).toBe("JsonSchema");
      expect(signed.credentialSchema.id).toBe(`https://opencred.dev/schemas/${c.id}/v1`);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Custom (inline) schemas
// ═══════════════════════════════════════════════════════════════════════════

describe("credentialSchema field — custom schemas", () => {
  it("prefers the DeDi schema URL when present", async () => {
    storeData["customSchemas"] = [
      {
        id: "custom:dedi-1",
        name: "DeDi Schema",
        schema: { type: "object", properties: { name: { type: "string" } } },
        createdAt: "2026-01-01T00:00:00Z",
        dediSchemaUrl: "https://dedi.example/lookup/example.com/schemas/Cred-v1",
      },
    ];

    const { keyId } = await importTestKey();

    const result = await callBuildAndSign({
      keyId,
      schemaId: "custom:dedi-1",
      issuerDid: "did:key:z6Mktest",
      inlineSchema: { type: "object", properties: { name: { type: "string" } } },
      credentialSubject: { name: "Jane" },
      validFrom: "2025-01-01T00:00:00Z",
      proofFormat: "vc-jwt",
    });

    expect(result.success).toBe(true);
    const signed = JSON.parse(result.signedCredential!);
    expect(signed.credentialSchema.id).toBe(
      "https://dedi.example/lookup/example.com/schemas/Cred-v1",
    );
    expect(signed.credentialSchema.type).toBe("JsonSchema");
  });

  it("uses user-provided URL when no DeDi URL is set", async () => {
    storeData["customSchemas"] = [
      {
        id: "custom:url-1",
        name: "URL Schema",
        schema: { type: "object", properties: { name: { type: "string" } } },
        createdAt: "2026-01-01T00:00:00Z",
      },
    ];

    const { keyId } = await importTestKey();

    const result = await callBuildAndSign({
      keyId,
      schemaId: "custom:url-1",
      issuerDid: "did:key:z6Mktest",
      inlineSchema: { type: "object", properties: { name: { type: "string" } } },
      credentialSubject: { name: "Jane" },
      validFrom: "2025-01-01T00:00:00Z",
      credentialSchemaUrl: "https://issuer.example/schemas/custom.json",
      proofFormat: "vc-jwt",
    });

    expect(result.success).toBe(true);
    const signed = JSON.parse(result.signedCredential!);
    expect(signed.credentialSchema.id).toBe("https://issuer.example/schemas/custom.json");
  });

  it("falls back to a base64 data URI when no URL is set", async () => {
    const inlineSchema = {
      type: "object",
      properties: { name: { type: "string" } },
      required: ["name"],
    };

    storeData["customSchemas"] = [
      {
        id: "custom:inline-1",
        name: "Inline Schema",
        schema: inlineSchema,
        createdAt: "2026-01-01T00:00:00Z",
      },
    ];

    const { keyId } = await importTestKey();

    const result = await callBuildAndSign({
      keyId,
      schemaId: "custom:inline-1",
      issuerDid: "did:key:z6Mktest",
      inlineSchema,
      credentialSubject: { name: "Jane" },
      validFrom: "2025-01-01T00:00:00Z",
      proofFormat: "vc-jwt",
    });

    expect(result.success).toBe(true);
    const signed = JSON.parse(result.signedCredential!);
    expect(signed.credentialSchema.type).toBe("JsonSchema");
    expect(signed.credentialSchema.id).toMatch(/^data:application\/schema\+json;base64,/);

    // Decode and confirm round-trip equality.
    const dataPart = (signed.credentialSchema.id as string).split(",")[1];
    const decoded = JSON.parse(Buffer.from(dataPart, "base64").toString("utf8"));
    expect(decoded).toEqual(inlineSchema);
  });

  it("data URI is well-formed even without a saved CustomSchemaEntry", async () => {
    const inlineSchema = {
      type: "object",
      properties: { foo: { type: "string" } },
    };

    const { keyId } = await importTestKey();

    const result = await callBuildAndSign({
      keyId,
      // schemaId is not "custom:..." here — purely ad-hoc inline.
      schemaId: "ad-hoc-schema",
      issuerDid: "did:key:z6Mktest",
      inlineSchema,
      credentialSubject: { foo: "bar" },
      validFrom: "2025-01-01T00:00:00Z",
      proofFormat: "vc-jwt",
    });

    expect(result.success).toBe(true);
    const signed = JSON.parse(result.signedCredential!);
    expect(signed.credentialSchema.id).toMatch(/^data:application\/schema\+json;base64,/);

    const dataPart = (signed.credentialSchema.id as string).split(",")[1];
    const decoded = JSON.parse(Buffer.from(dataPart, "base64").toString("utf8"));
    expect(decoded).toEqual(inlineSchema);
  });
});
