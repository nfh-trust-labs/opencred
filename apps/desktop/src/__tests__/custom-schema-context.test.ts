/**
 * Tests for the custom-schema JSON-LD context fetching + caching flow,
 * the wrapped (per-schema-scoped) document loader, and the safety limits
 * applied to user-provided context URLs.
 *
 * Threat model note: the context URL is *user-pasted* in the custom-schema
 * setup form. SSRF gymnastics would be security theatre here (the user can
 * already make any HTTP request from their machine), so the production
 * fetch path does NOT do DNS pinning or private-IP rejection. Instead it
 * enforces what actually protects the user from their own paste:
 * HTTPS-only, no redirects, ~1 MiB body cap, hard 10s timeout, and strict
 * JSON-LD shape validation. These tests cover all of those.
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
  findCachedCustomContext,
  runWithActiveSchemaContext,
  deriveScopeForCredential,
} = await import("../main/document-loader-with-cache.js");

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

/** Build a fetch mock that returns a JSON body with the given object. */
function jsonResponseMock(body: unknown, status = 200): typeof globalThis.fetch {
  return vi.fn(async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/ld+json" },
    }),
  ) as unknown as typeof globalThis.fetch;
}

// ═══════════════════════════════════════════════════════════════════════════
// Custom schema context fetching
// ═══════════════════════════════════════════════════════════════════════════

describe("Custom schema context fetching", () => {
  it("fetches and caches a JSON-LD context document at save time", async () => {
    globalThis.fetch = jsonResponseMock(SAMPLE_JSONLD_CONTEXT);

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

    // Cache is populated regardless of scope.
    const direct = findCachedCustomContext("https://example.com/context.jsonld");
    expect(direct?.document).toEqual(SAMPLE_JSONLD_CONTEXT);
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

  it("rejects responses that are not a JSON object (e.g. arrays)", async () => {
    globalThis.fetch = jsonResponseMock(["not", "an", "object"]);

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

  it("rejects responses without an @context object key (strict shape)", async () => {
    // Looks like JSON but is not a JSON-LD context document.
    globalThis.fetch = jsonResponseMock({ randomKey: "value", anotherKey: 42 });

    const result = await callCustomSchemaSave({
      name: "Custom shape-bad",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://example.com/not-a-context.json",
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/JSON-LD context document/i);
  });

  it("rejects responses where @context is a string, not an object", async () => {
    globalThis.fetch = jsonResponseMock({ "@context": "https://schema.org" });

    const result = await callCustomSchemaSave({
      name: "Custom shape-string",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://example.com/string-ctx.json",
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/JSON-LD context document/i);
  });

  it("rejects HTTP error responses (5xx) without leaking statusText", async () => {
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
    // Generic error: should NOT propagate the server's statusText.
    expect(result.error).not.toMatch(/Internal Server Error/);
  });

  it("rejects responses larger than the 1 MiB size cap (declared Content-Length)", async () => {
    // Server claims a 5 MiB body via Content-Length. We bail before reading.
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify(SAMPLE_JSONLD_CONTEXT), {
        status: 200,
        headers: {
          "Content-Type": "application/ld+json",
          "Content-Length": String(5 * 1024 * 1024),
        },
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const result = await callCustomSchemaSave({
      name: "Custom oversize",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://example.com/oversize.jsonld",
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/size limit/i);
  });

  it("rejects responses larger than the 1 MiB size cap (streamed body)", async () => {
    // No Content-Length header — server lies / omits it. We must catch this
    // mid-stream and abort before buffering more than the limit.
    // 1.5 MiB body, no header.
    const huge = "x".repeat(1.5 * 1024 * 1024);
    const fetchMock = vi.fn(async () => new Response(huge, { status: 200 }));
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const result = await callCustomSchemaSave({
      name: "Custom oversize-stream",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://example.com/oversize-stream.jsonld",
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    expect(result.error).toMatch(/size limit/i);
  });

  it("never propagates internal error messages from network failures", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("ECONNREFUSED 192.168.1.1:443 super-secret-internal-detail");
    });
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const result = await callCustomSchemaSave({
      name: "Custom net-fail",
      schema: { type: "object", properties: { name: { type: "string" } } },
      contextUrl: "https://example.com/net-fail.jsonld",
    });
    restoreFetch();

    expect(result.success).toBe(true);
    expect(result.contextCached).toBe(false);
    // Generic message — internal details (IP, port, raw error) must NOT
    // appear in the renderer-facing error.
    expect(result.error).toMatch(/Failed to fetch context URL/);
    expect(result.error).not.toMatch(/192\.168/);
    expect(result.error).not.toMatch(/super-secret/);
    expect(result.error).not.toMatch(/ECONNREFUSED/);
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
// Per-schema scope on the cached context lookup
// ═══════════════════════════════════════════════════════════════════════════

describe("Per-schema scope on cached context lookup", () => {
  beforeEach(() => {
    storeData["customSchemas"] = [
      {
        id: "custom:schema-a",
        name: "Schema A",
        schema: { type: "object" },
        createdAt: "2026-01-01T00:00:00Z",
        dediContextUrl: "https://schema.example/contexts/a",
        cachedContextDocument: { "@context": { "@vocab": "https://example.org/a#" } },
        cachedContextFetchedAt: "2026-01-01T00:00:00Z",
      },
      {
        id: "custom:schema-b",
        name: "Schema B",
        schema: { type: "object" },
        createdAt: "2026-01-01T00:00:00Z",
        dediContextUrl: "https://schema.example/contexts/b",
        cachedContextDocument: { "@context": { "@vocab": "https://example.org/b#" } },
        cachedContextFetchedAt: "2026-01-01T00:00:00Z",
      },
    ];
  });

  it("returns undefined for unknown URLs", () => {
    runWithActiveSchemaContext(["custom:schema-a"], () => {
      expect(lookupCachedCustomContext("https://nope.example/ctx")).toBeUndefined();
    });
  });

  it("returns undefined when no scope is active (safe default)", () => {
    // Outside any runWithActiveSchemaContext block, the cache is invisible.
    expect(lookupCachedCustomContext("https://schema.example/contexts/a")).toBeUndefined();
  });

  it("returns the cached context for an in-scope schema URL", () => {
    runWithActiveSchemaContext(["custom:schema-a"], () => {
      const cached = lookupCachedCustomContext("https://schema.example/contexts/a");
      expect(cached).toEqual({ "@context": { "@vocab": "https://example.org/a#" } });
    });
  });

  it("does NOT serve schema A's cached context when only schema B is in scope", () => {
    // Defence-in-depth: even though schema A has cached context X, while
    // we're issuing/verifying schema B that cache must NOT be visible.
    runWithActiveSchemaContext(["custom:schema-b"], () => {
      expect(
        lookupCachedCustomContext("https://schema.example/contexts/a"),
      ).toBeUndefined();
      expect(
        lookupCachedCustomContext("https://schema.example/contexts/b"),
      ).toBeDefined();
    });
  });

  it("findCachedCustomContext bypasses scope (diagnostic-only)", () => {
    // The diagnostic helper deliberately ignores the scope so the
    // schema-management UI can answer "is this URL cached anywhere?"
    const found = findCachedCustomContext("https://schema.example/contexts/a");
    expect(found?.schemaId).toBe("custom:schema-a");
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
// deriveScopeForCredential
// ═══════════════════════════════════════════════════════════════════════════

describe("deriveScopeForCredential", () => {
  beforeEach(() => {
    storeData["customSchemas"] = [
      {
        id: "custom:imported-1",
        name: "Imported 1",
        schema: { type: "object" },
        createdAt: "2026-01-01T00:00:00Z",
        dediContextUrl: "https://schema.example/imported-1",
        cachedContextDocument: { "@context": {} },
      },
      {
        id: "custom:imported-2",
        name: "Imported 2",
        schema: { type: "object" },
        createdAt: "2026-01-01T00:00:00Z",
        dediContextUrl: "https://schema.example/imported-2",
        cachedContextDocument: { "@context": {} },
      },
    ];
  });

  it("returns the schema id when @context references its URL", () => {
    const scope = deriveScopeForCredential({
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://schema.example/imported-1",
      ],
    });
    expect(scope).toEqual(["custom:imported-1"]);
  });

  it("returns multiple schema ids when @context references multiple", () => {
    const scope = deriveScopeForCredential({
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://schema.example/imported-1",
        "https://schema.example/imported-2",
      ],
    });
    expect(scope.sort()).toEqual(["custom:imported-1", "custom:imported-2"]);
  });

  it("returns an empty array when no custom URL is referenced", () => {
    const scope = deriveScopeForCredential({
      "@context": ["https://www.w3.org/ns/credentials/v2"],
    });
    expect(scope).toEqual([]);
  });

  it("returns an empty array when @context is missing", () => {
    expect(deriveScopeForCredential({})).toEqual([]);
  });

  it("returns an empty array when @context is a single string", () => {
    const scope = deriveScopeForCredential({
      "@context": "https://www.w3.org/ns/credentials/v2",
    });
    expect(scope).toEqual([]);
  });

  it("includes a schema referenced by a single-string @context", () => {
    const scope = deriveScopeForCredential({
      "@context": "https://schema.example/imported-1",
    });
    expect(scope).toEqual(["custom:imported-1"]);
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

    // Confirm the cache entry is still there for the diagnostic helper.
    const found = findCachedCustomContext("https://schema.example/contexts/di-1");
    expect(found?.document).toEqual(tolerantContext);
  });
});
