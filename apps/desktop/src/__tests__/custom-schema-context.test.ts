/**
 * Tests for the custom-schema JSON-LD context fetching + caching flow,
 * the wrapped document loader, and the SSRF protection on user-provided
 * context URLs.
 *
 * SECURITY NOTE: every test path that exercises the fetch goes through
 * the production handler — there are no shortcuts around HTTPS / SSRF /
 * shape validation. We mock `node:dns` so we can simulate "URL resolves
 * to public IP" without depending on real DNS.
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

// We mock the dns lookup so we can simulate "URL resolves to public IP"
// without needing real network access. The SSRF guard sits *after* this,
// so the production code path still runs end-to-end.
const dnsLookupMock = vi.fn();
vi.mock("node:dns", async () => {
  const actual = await vi.importActual<typeof import("node:dns")>("node:dns");
  return {
    ...actual,
    promises: {
      ...actual.promises,
      lookup: dnsLookupMock,
    },
  };
});

// Initialise store before importing IPC handlers.
const { initStore } = await import("../main/store");
initStore();

const { registerIpcHandlers } = await import("../main/ipc-handlers");
registerIpcHandlers();

const { IPC_CHANNELS } = await import("../shared/ipc-channels");
const {
  installCustomContextResolver,
  uninstallCustomContextResolver,
  lookupCachedCustomContext,
} = await import("../main/document-loader-with-cache");

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const fakeEvent = null as unknown;

let originalFetch: typeof globalThis.fetch;

const SAMPLE_JSONLD_CONTEXT = {
  "@context": {
    "@version": 1.1,
    "@protected": true,
    name: "https://schema.org/name",
    age: "https://schema.org/age",
  },
};

let tmpDir: string;
let ecKeyPath: string;

const { privateKey: testEcKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-ctx-test-"));
  ecKeyPath = path.join(tmpDir, "test-p256.pem");
  fs.writeFileSync(ecKeyPath, testEcKey.export({ format: "pem", type: "pkcs8" }) as string);
  installCustomContextResolver();
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  uninstallCustomContextResolver();
});

beforeEach(() => {
  storeData["customSchemas"] = [];
  storeData["recentTemplates"] = [];
  storeData["dediPublishedSchemas"] = [];
  dnsLookupMock.mockReset();
  // Default: pretend hostnames resolve to a benign public IP.
  dnsLookupMock.mockResolvedValue({ address: "203.0.113.10", family: 4 });
  originalFetch = globalThis.fetch;
});

function restoreFetch(): void {
  globalThis.fetch = originalFetch;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function callCustomSchemaSave(
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const handler = registeredHandlers[IPC_CHANNELS.CUSTOM_SCHEMA_SAVE];
  return (await handler(fakeEvent, payload)) as Record<string, unknown>;
}

async function importTestKey(): Promise<{ keyId: string }> {
  const handler = registeredHandlers[IPC_CHANNELS.KEY_IMPORT];
  const result = await handler(fakeEvent, { filePath: ecKeyPath }) as {
    success: boolean;
    key: { id: string };
  };
  expect(result.success).toBe(true);
  return { keyId: result.key.id };
}

async function callBuildAndSign(opts: Record<string, unknown>): Promise<Record<string, unknown>> {
  const handler = registeredHandlers[IPC_CHANNELS.BUILD_AND_SIGN];
  return (await handler(fakeEvent, opts)) as Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Custom schema context fetching
// ═══════════════════════════════════════════════════════════════════════════

describe("Custom schema context fetching", () => {
  it("fetches and caches a JSON-LD context document at save time", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify(SAMPLE_JSONLD_CONTEXT), {
        status: 200,
        headers: { "Content-Type": "application/ld+json" },
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const result = await callCustomSchemaSave({
      name: "Custom A",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://example.com/context.jsonld",
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(true);
    expect(typeof result.cachedContextFetchedAt).toBe("string");
    expect(result.contextUrl).toBe("https://example.com/context.jsonld");

    const stored = (storeData["customSchemas"] as Array<Record<string, unknown>>)[0];
    expect(stored).toBeDefined();
    expect(stored.cachedContextDocument).toEqual(SAMPLE_JSONLD_CONTEXT);
    expect(typeof stored.cachedContextFetchedAt).toBe("string");

    const cached = lookupCachedCustomContext("https://example.com/context.jsonld");
    expect(cached).toEqual(SAMPLE_JSONLD_CONTEXT);
  });

  it("rejects non-HTTPS context URLs", async () => {
    const result = await callCustomSchemaSave({
      name: "Custom B",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "http://example.com/context.jsonld",
    });

    expect(result.success).toBe(true); // schema saved
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/HTTPS/i);
  });

  it("rejects URLs that resolve to a private IPv4 address (SSRF)", async () => {
    dnsLookupMock.mockResolvedValueOnce({ address: "192.168.1.42", family: 4 });

    const result = await callCustomSchemaSave({
      name: "Custom C",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://internal.example.com/context.jsonld",
    });

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/private IP/i);
  });

  it("rejects URLs that resolve to loopback (127.0.0.1)", async () => {
    dnsLookupMock.mockResolvedValueOnce({ address: "127.0.0.1", family: 4 });

    const result = await callCustomSchemaSave({
      name: "Custom D",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://localhost.example.com/context.jsonld",
    });

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/private IP/i);
  });

  it("rejects URLs that resolve to IPv6 loopback (::1)", async () => {
    dnsLookupMock.mockResolvedValueOnce({ address: "::1", family: 6 });

    const result = await callCustomSchemaSave({
      name: "Custom E",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://internal-v6.example.com/context.jsonld",
    });

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/private IP/i);
  });

  it("rejects responses that are not a JSON object (e.g. arrays)", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify(["not", "an", "object"]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const result = await callCustomSchemaSave({
      name: "Custom F",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://example.com/array.json",
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/not a JSON object/i);
  });

  it("rejects HTTP error responses (5xx)", async () => {
    const fetchMock = vi.fn(async () =>
      new Response("server error", { status: 500, statusText: "Internal Server Error" }),
    );
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const result = await callCustomSchemaSave({
      name: "Custom G",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://example.com/broken.jsonld",
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/HTTP 500/);
  });

  it("does not fetch when no context URL is supplied", async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const result = await callCustomSchemaSave({
      name: "Custom H",
      schema: { type: "object", properties: { name: { type: "string" } } },
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Wrapped document loader behaviour
// ═══════════════════════════════════════════════════════════════════════════

describe("Wrapped document loader", () => {
  it("returns undefined when no custom schema matches", () => {
    expect(lookupCachedCustomContext("https://nope.example/ctx")).toBeUndefined();
  });

  it("returns the cached context document for a matching dediContextUrl", () => {
    storeData["customSchemas"] = [
      {
        id: "custom:abc",
        name: "Test",
        schema: { type: "object" },
        createdAt: "2026-01-01T00:00:00Z",
        dediContextUrl: "https://schema.example/context",
        cachedContextDocument: SAMPLE_JSONLD_CONTEXT,
        cachedContextFetchedAt: "2026-01-01T00:00:00Z",
      },
    ];

    const cached = lookupCachedCustomContext("https://schema.example/context");
    expect(cached).toEqual(SAMPLE_JSONLD_CONTEXT);
  });

  it("falls through bundled contexts before custom ones", async () => {
    const { createDocumentLoader } = await import("@opencred/vc-core");
    const bundledLoader = createDocumentLoader();
    // The bundled loader should resolve W3C credentials/v2 even though we
    // never registered it as a custom context.
    const result = bundledLoader("https://www.w3.org/ns/credentials/v2");
    expect(result.document).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Cached context is consumed during data-integrity issuance
// ═══════════════════════════════════════════════════════════════════════════

describe("Cached custom context is consumed by data-integrity canonicalization", () => {
  it("issues a custom-schema VC with a cached context (proof attaches successfully)", async () => {
    // A tolerant @vocab context lets all credentialSubject fields be mapped
    // — this is what `safe: true` strict canonicalization needs.
    const tolerantContext = {
      "@context": {
        "@version": 1.1,
        "@vocab": "https://example.org/vocab#",
      },
    };

    storeData["customSchemas"] = [
      {
        id: "custom:di-1",
        name: "DI Schema",
        schema: { type: "object", properties: { name: { type: "string" } } },
        createdAt: "2026-01-01T00:00:00Z",
        dediContextUrl: "https://schema.example/contexts/di-1",
        cachedContextDocument: tolerantContext,
        cachedContextFetchedAt: "2026-01-01T00:00:00Z",
      },
    ];

    const { keyId } = await importTestKey();

    const result = await callBuildAndSign({
      keyId,
      schemaId: "custom:di-1",
      issuerDid: "did:key:z6Mktest",
      inlineSchema: { type: "object", properties: { name: { type: "string" } } },
      credentialSubject: { name: "Jane" },
      validFrom: "2025-01-01T00:00:00Z",
      proofFormat: "data-integrity",
    });

    if (!result.success) {
      throw new Error(`build & sign failed: ${result.error as string}`);
    }
    expect(result.success).toBe(true);
    const signed = JSON.parse(result.signedCredential as string);
    expect(signed.proof.type).toBe("DataIntegrityProof");
    expect(signed.proof.cryptosuite).toBe("ecdsa-rdfc-2019");

    // Confirm the wrapped loader still serves the cached context.
    const cached = lookupCachedCustomContext("https://schema.example/contexts/di-1");
    expect(cached).toEqual(tolerantContext);
  });
});
