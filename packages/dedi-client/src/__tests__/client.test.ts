import { describe, it, expect, vi, beforeEach } from "vitest";
import { DeDiClientError } from "@opencred/shared";
import { DeDiClient } from "../adapter/client.js";
import { DeDiApiClient } from "../api/api-client.js";
import type { ContextRecord, SchemaRecord } from "../adapter/types.js";
import {
  REVOCATION_REGISTRY,
  PUBLIC_KEY_REGISTRY,
  SCHEMA_REGISTRY,
  CONTEXT_REGISTRY,
} from "../adapter/registry-names.js";

// Mock the DeDiApiClient
vi.mock("../api/api-client.js", () => {
  const MockDeDiApiClient = vi.fn();
  MockDeDiApiClient.prototype.publishRecord = vi.fn();
  MockDeDiApiClient.prototype.lookupRecord = vi.fn();
  MockDeDiApiClient.prototype.search = vi.fn();
  MockDeDiApiClient.prototype.createNamespace = vi.fn();
  MockDeDiApiClient.prototype.createRegistry = vi.fn();
  return { DeDiApiClient: MockDeDiApiClient };
});

function createClient(defaultNamespace?: string) {
  return new DeDiClient({
    baseUrl: "https://dedi.example.com",
    timeoutMs: 5000,
    maxRetries: 0,
    circuitBreakerThreshold: 5,
    auth: { type: "api-key", apiKey: "dk_test" },
    defaultNamespace,
  });
}

function mockApi(): InstanceType<typeof DeDiApiClient> {
  // Get the most recent instance created by the mock constructor
  const instances = vi.mocked(DeDiApiClient).mock.instances;
  return instances[instances.length - 1]!;
}

describe("DeDiClient (adapter)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── Namespace resolution ─────────────────────────────────────────

  describe("namespace resolution", () => {
    it("uses defaultNamespace when no explicit namespace provided", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({ records: [], total: 0 });

      await client.queryRevocationHash("abc");

      expect(api.search).toHaveBeenCalledWith("example.com", expect.any(Object));
    });

    it("uses explicit namespace over defaultNamespace", async () => {
      const client = createClient("default.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({ records: [], total: 0 });

      await client.queryRevocationHash("abc", "explicit.com");

      expect(api.search).toHaveBeenCalledWith("explicit.com", expect.any(Object));
    });

    it("throws when no namespace available", async () => {
      const client = createClient(); // no default
      await expect(client.queryRevocationHash("abc")).rejects.toThrow("No namespace provided");
    });
  });

  // ── publishRevocationHash ────────────────────────────────────────

  describe("publishRevocationHash", () => {
    it("publishes a record to the vc-revocation-registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "abc",
        registry: REVOCATION_REGISTRY,
        namespace: "example.com",
        detail: {
          hash: "abc",
          revoked: true,
          revokedAt: "2026-01-01T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      const result = await client.publishRevocationHash("abc");

      expect(api.publishRecord).toHaveBeenCalledWith(
        "example.com",
        REVOCATION_REGISTRY,
        "abc",
        expect.objectContaining({ hash: "abc", revoked: true }),
      );
      expect(result).toEqual(expect.objectContaining({ hash: "abc", revoked: true }));
    });

    it("throws when API returns invalid revocation detail", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "abc",
        registry: REVOCATION_REGISTRY,
        namespace: "example.com",
        detail: { invalid: true },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.publishRevocationHash("abc")).rejects.toThrow(
        "Revocation hash detail missing required field: hash",
      );
    });
  });

  // ── queryRevocationHash ──────────────────────────────────────────

  describe("queryRevocationHash", () => {
    it("searches for hash in vc-revocation-registry and returns found record", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({
        records: [
          {
            name: "abc",
            registry: REVOCATION_REGISTRY,
            namespace: "example.com",
            detail: {
              hash: "abc",
              revoked: true,
              revokedAt: "2026-01-01T00:00:00Z",
            },
            state: "live",
            version: 1,
            created_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-01T00:00:00Z",
          },
        ],
        total: 1,
      });

      const result = await client.queryRevocationHash("abc");

      expect(api.search).toHaveBeenCalledWith("example.com", {
        registry_name: REVOCATION_REGISTRY,
        "detail.hash": "abc",
      });
      expect(result).toEqual(expect.objectContaining({ hash: "abc", revoked: true }));
    });

    it("returns { revoked: false } when hash not found", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({ records: [], total: 0 });

      const result = await client.queryRevocationHash("missing");

      expect(result).toEqual({ hash: "missing", revoked: false });
    });

    it("throws on 404 instead of treating as not-revoked", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockRejectedValue(new DeDiClientError("DeDi API error: 404", 404));

      await expect(client.queryRevocationHash("missing")).rejects.toThrow(DeDiClientError);
    });

    it("re-throws non-404 errors", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockRejectedValue(new DeDiClientError("DeDi API error: 500", 502));

      await expect(client.queryRevocationHash("hash")).rejects.toThrow("DeDi API error: 500");
    });

    it("throws when revoked record is missing revokedAt", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({
        records: [
          {
            name: "abc",
            registry: REVOCATION_REGISTRY,
            namespace: "example.com",
            detail: { hash: "abc", revoked: true },
            state: "live",
            version: 1,
            created_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-01T00:00:00Z",
          },
        ],
        total: 1,
      });

      await expect(client.queryRevocationHash("abc")).rejects.toThrow(
        "Revocation hash detail missing required field: revokedAt",
      );
    });
  });

  // ── resolveDID ───────────────────────────────────────────────────

  describe("resolveDID", () => {
    it("looks up DID record in public_key_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const didRecord = {
        did: "did:key:z6Mk123",
        document: { id: "did:key:z6Mk123" },
        resolvedAt: "2026-01-01T00:00:00Z",
      };

      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "did-key-z6Mk123",
        registry: PUBLIC_KEY_REGISTRY,
        namespace: "example.com",
        detail: didRecord,
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      const result = await client.resolveDID("did:key:z6Mk123");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        expect.any(String), // DID to record name conversion
      );
      expect(result).toEqual(didRecord);
    });

    it("converts DID colons to hyphens for record name", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "did-key-z6Mk123",
        registry: PUBLIC_KEY_REGISTRY,
        namespace: "example.com",
        detail: { did: "did:key:z6Mk123", document: {}, resolvedAt: "" },
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      await client.resolveDID("did:key:z6Mk123");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        "did-key-z6Mk123",
      );
    });

    it("throws when API returns invalid DID record", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "did-key-z6Mk123",
        registry: PUBLIC_KEY_REGISTRY,
        namespace: "example.com",
        detail: { invalid: true },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DID record detail missing required field: did",
      );
    });
  });

  // ── ensureRegistries ─────────────────────────────────────────────

  describe("ensureRegistries", () => {
    it("creates namespace and all three registries", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.createNamespace).mockResolvedValue({
        name: "example.com",
        description: "OpenCred namespace",
        state: "active",
        verified: false,
        created_at: "",
        updated_at: "",
      });
      vi.mocked(api.createRegistry).mockResolvedValue({
        name: "test",
        namespace: "example.com",
        schema: {},
        tag: "Revoke",
        state: "active",
        record_count: 0,
        created_at: "",
        updated_at: "",
      });

      await client.ensureRegistries("example.com");

      expect(api.createNamespace).toHaveBeenCalledWith("example.com", expect.any(String));
      expect(api.createRegistry).toHaveBeenCalledTimes(4);
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        REVOCATION_REGISTRY,
        expect.objectContaining({
          properties: expect.objectContaining({ hash: { type: "string" } }),
        }),
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        expect.objectContaining({
          properties: expect.objectContaining({ did: { type: "string" } }),
        }),
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        SCHEMA_REGISTRY,
        expect.objectContaining({
          properties: expect.objectContaining({ schemaId: { type: "string" } }),
        }),
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        CONTEXT_REGISTRY,
        expect.any(Object),
        "custom",
      );
    });

    it("treats 409 Conflict as success (idempotent)", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.createNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409),
      );
      vi.mocked(api.createRegistry).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409),
      );

      // Should not throw
      await expect(client.ensureRegistries("example.com")).resolves.toBeUndefined();
    });

    it("re-throws non-409 errors", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.createNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 500", 502),
      );

      await expect(client.ensureRegistries("example.com")).rejects.toThrow("DeDi API error: 500");
    });
  });

  // ── apiClient getter ─────────────────────────────────────────────

  describe("apiClient getter", () => {
    it("exposes the underlying DeDiApiClient", () => {
      const client = createClient("example.com");
      expect(client.apiClient).toBeInstanceOf(DeDiApiClient);
    });
  });

  // ── constructor validation ──────────────────────────────────────

  describe("constructor validation", () => {
    // DeDiApiClient constructor is mocked in this test file.
    // Validation tests for numeric config are in api-client.test.ts.
    // This section verifies DeDiClient forwards config correctly.

    it("passes config through to DeDiApiClient", () => {
      createClient("example.com");
      expect(DeDiApiClient).toHaveBeenCalledWith(
        expect.objectContaining({
          baseUrl: "https://dedi.example.com",
          timeoutMs: 5000,
          maxRetries: 0,
          circuitBreakerThreshold: 5,
        }),
      );
    });
  });

  // ── publishDID ───────────────────────────────────────────────────

  describe("publishDID", () => {
    it("publishes a DID document to the public_key_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const didDocument = { id: "did:web:example.com", verificationMethod: [] };
      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "did-web-example.com",
        registry: PUBLIC_KEY_REGISTRY,
        namespace: "example.com",
        detail: {
          did: "did:web:example.com",
          document: didDocument,
          resolvedAt: "2026-03-25T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      const result = await client.publishDID("did:web:example.com", didDocument);

      expect(api.publishRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        "did-web-example.com",
        expect.objectContaining({ did: "did:web:example.com", document: didDocument }),
      );
      expect(result.published).toBe(true);
      expect(result.recordName).toBe("did-web-example.com");
      expect(result.namespace).toBe("example.com");
    });
  });

  // ── publishSchema ────────────────────────────────────────────────

  describe("publishSchema", () => {
    const testSchema: SchemaRecord = {
      schemaId: "functional-identity/v1",
      version: "1",
      schema: { type: "object", properties: {} },
      contextUrl:
        "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/functional-identity/v1/context.json",
      checksum: "abc123",
      publishedAt: "2026-03-25T00:00:00Z",
    };

    it("publishes a schema to the schema_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "functional-identity-v1",
        registry: SCHEMA_REGISTRY,
        namespace: "example.com",
        detail: testSchema,
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      const result = await client.publishSchema(testSchema);

      expect(api.publishRecord).toHaveBeenCalledWith(
        "example.com",
        SCHEMA_REGISTRY,
        "functional-identity-v1",
        testSchema,
      );
      expect(result.published).toBe(true);
      expect(result.recordName).toBe("functional-identity-v1");
    });
  });

  // ── resolveSchema ────────────────────────────────────────────────

  describe("resolveSchema", () => {
    it("looks up a schema from the schema_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const schemaDetail: SchemaRecord = {
        schemaId: "functional-identity/v1",
        version: "1",
        schema: { type: "object" },
        checksum: "abc",
        publishedAt: "2026-03-25T00:00:00Z",
      };
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "functional-identity-v1",
        registry: SCHEMA_REGISTRY,
        namespace: "example.com",
        detail: schemaDetail,
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      const result = await client.resolveSchema("functional-identity/v1", "1");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        SCHEMA_REGISTRY,
        "functional-identity-v1",
      );
      expect(result.schemaId).toBe("functional-identity/v1");
    });

    it("throws on malformed schema record", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "bad-v1",
        registry: SCHEMA_REGISTRY,
        namespace: "example.com",
        detail: { schemaId: "bad" },
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      await expect(client.resolveSchema("bad", "1")).rejects.toThrow(
        "Schema record detail missing required field",
      );
    });

    it("throws when checksum is not a string", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "test-v1",
        registry: SCHEMA_REGISTRY,
        namespace: "example.com",
        detail: {
          schemaId: "test",
          version: "1",
          schema: { type: "object" },
          checksum: 12345,
          publishedAt: "2026-01-01T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      await expect(client.resolveSchema("test", "1")).rejects.toThrow(
        "Schema record field 'checksum' must be a string",
      );
    });

    it("throws when publishedAt is not a string", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "test-v1",
        registry: SCHEMA_REGISTRY,
        namespace: "example.com",
        detail: {
          schemaId: "test",
          version: "1",
          schema: { type: "object" },
          checksum: "abc",
          publishedAt: null,
        },
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      await expect(client.resolveSchema("test", "1")).rejects.toThrow(
        "Schema record field 'publishedAt' must be a string",
      );
    });
  });

  // ── resolveContext ───────────────────────────────────────────────

  describe("resolveContext", () => {
    it("looks up a context from the context_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const contextDetail: ContextRecord = {
        schemaId: "functional-identity/v1",
        version: "1",
        context: { "@context": {} },
        publishedAt: "2026-03-25T00:00:00Z",
      };
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "functional-identity-ctx-v1",
        registry: CONTEXT_REGISTRY,
        namespace: "example.com",
        detail: contextDetail,
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      const result = await client.resolveContext("functional-identity/v1", "1");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        CONTEXT_REGISTRY,
        expect.any(String),
      );
      expect(result.schemaId).toBe("functional-identity/v1");
    });

    it("throws on malformed context record", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "bad-ctx-v1",
        registry: CONTEXT_REGISTRY,
        namespace: "example.com",
        detail: { schemaId: "bad" },
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      await expect(client.resolveContext("bad", "1")).rejects.toThrow(
        "Context record detail missing required field",
      );
    });

    it("throws when publishedAt is not a string", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "test-ctx-v1",
        registry: CONTEXT_REGISTRY,
        namespace: "example.com",
        detail: {
          schemaId: "test",
          version: "1",
          context: { "@context": {} },
          publishedAt: 12345,
        },
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      await expect(client.resolveContext("test", "1")).rejects.toThrow(
        "Context record field 'publishedAt' must be a string",
      );
    });

    it("throws when context is not an object", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "test-ctx-v1",
        registry: CONTEXT_REGISTRY,
        namespace: "example.com",
        detail: {
          schemaId: "test",
          version: "1",
          context: "not-an-object",
          publishedAt: "2026-01-01T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      await expect(client.resolveContext("test", "1")).rejects.toThrow(
        "Context record field 'context' must be an object",
      );
    });
  });

  // ── DeDi record wrapper validation ──────────────────────────────

  describe("DeDi record wrapper validation", () => {
    it("throws when lookupRecord returns response without detail field", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "test",
      } as never);

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DeDi API lookupRecord response missing required field: detail",
      );
    });

    it("throws when lookupRecord returns response without name field", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        detail: { did: "did:key:z6Mk123", document: {}, resolvedAt: "" },
      } as never);

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DeDi API lookupRecord response missing required field: name",
      );
    });

    it("throws when publishRecord returns null", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue(null as never);

      await expect(client.publishRevocationHash("abc")).rejects.toThrow(
        "DeDi API publishRecord response is missing or not an object",
      );
    });
  });

  // ── Search result wrapper validation ────────────────────────────

  describe("search result wrapper validation", () => {
    it("throws when search returns response without records array", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({ total: 0 } as never);

      await expect(client.queryRevocationHash("abc")).rejects.toThrow(
        "DeDi API search response field 'records' must be an array",
      );
    });

    it("throws when search returns null", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue(null as never);

      await expect(client.queryRevocationHash("abc")).rejects.toThrow(
        "DeDi API search response is missing or not an object",
      );
    });
  });
});
