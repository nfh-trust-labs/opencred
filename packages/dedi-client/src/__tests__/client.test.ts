import { describe, it, expect, vi, beforeEach } from "vitest";
import { DeDiClientError } from "@opencred/shared";
import { DeDiClient } from "../adapter/client.js";
import { DeDiApiClient } from "../api/api-client.js";
import type { DelegationRecord, SchemaRecord } from "../adapter/types.js";
import {
  REVOCATION_REGISTRY,
  DELEGATION_REGISTRY,
  PUBLIC_KEY_REGISTRY,
  SCHEMA_REGISTRY,
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

function validDelegation(
  overrides?: Partial<DelegationRecord>,
): DelegationRecord {
  return {
    id: "del-1",
    issuerDid: "did:key:issuer",
    delegateDid: "did:key:delegate",
    scope: { credentialTypes: ["UniversityDegreeCredential"], namespaces: ["education"] },
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    certificate: {},
    ...overrides,
  };
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

      expect(api.search).toHaveBeenCalledWith(
        "example.com",
        expect.any(Object),
      );
    });

    it("uses explicit namespace over defaultNamespace", async () => {
      const client = createClient("default.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({ records: [], total: 0 });

      await client.queryRevocationHash("abc", "explicit.com");

      expect(api.search).toHaveBeenCalledWith(
        "explicit.com",
        expect.any(Object),
      );
    });

    it("throws when no namespace available", async () => {
      const client = createClient(); // no default
      await expect(client.queryRevocationHash("abc")).rejects.toThrow(
        "No namespace provided",
      );
    });
  });

  // ── publishRevocationHash ────────────────────────────────────────

  describe("publishRevocationHash", () => {
    it("publishes a record to the revocation_list registry", async () => {
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
      expect(result).toEqual(
        expect.objectContaining({ hash: "abc", revoked: true }),
      );
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
    it("searches for hash in revocation_list and returns found record", async () => {
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
      expect(result).toEqual(
        expect.objectContaining({ hash: "abc", revoked: true }),
      );
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
      vi.mocked(api.search).mockRejectedValue(
        new DeDiClientError("DeDi API error: 404", 404),
      );

      await expect(client.queryRevocationHash("missing")).rejects.toThrow(
        DeDiClientError,
      );
    });

    it("re-throws non-404 errors", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockRejectedValue(
        new DeDiClientError("DeDi API error: 500", 502),
      );

      await expect(client.queryRevocationHash("hash")).rejects.toThrow(
        "DeDi API error: 500",
      );
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

  // ── registerDelegation ───────────────────────────────────────────

  describe("registerDelegation", () => {
    it("publishes delegation to delegation_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const delegation = validDelegation();

      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: delegation,
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      const result = await client.registerDelegation(delegation);

      expect(api.publishRecord).toHaveBeenCalledWith(
        "example.com",
        DELEGATION_REGISTRY,
        "del-1",
        delegation,
      );
      expect(result).toEqual(delegation);
    });
  });

  // ── registerDelegation validation ──────────────────────────────

  describe("registerDelegation validation", () => {
    it("throws when scope is empty (both credentialTypes and namespaces empty)", async () => {
      const client = createClient("example.com");
      const delegation = validDelegation({
        scope: { credentialTypes: [], namespaces: [] },
      });

      await expect(client.registerDelegation(delegation)).rejects.toThrow(
        "Delegation scope must not be empty",
      );
    });

    it("allows scope with only credentialTypes", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const delegation = validDelegation({
        scope: { credentialTypes: ["TestCredential"], namespaces: [] },
      });

      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: delegation,
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      const result = await client.registerDelegation(delegation);
      expect(result).toEqual(delegation);
    });

    it("allows scope with only namespaces", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const delegation = validDelegation({
        scope: { credentialTypes: [], namespaces: ["education"] },
      });

      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: delegation,
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      const result = await client.registerDelegation(delegation);
      expect(result).toEqual(delegation);
    });

    it("throws when validFrom is not a valid date", async () => {
      const client = createClient("example.com");
      const delegation = validDelegation({ validFrom: "not-a-date" });

      await expect(client.registerDelegation(delegation)).rejects.toThrow(
        "validFrom is not a valid date",
      );
    });

    it("throws when validUntil is not a valid date", async () => {
      const client = createClient("example.com");
      const delegation = validDelegation({ validUntil: "not-a-date" });

      await expect(client.registerDelegation(delegation)).rejects.toThrow(
        "validUntil is not a valid date",
      );
    });

    it("throws when validFrom >= validUntil", async () => {
      const client = createClient("example.com");
      const delegation = validDelegation({
        validFrom: "2027-01-01T00:00:00Z",
        validUntil: "2026-01-01T00:00:00Z",
      });

      await expect(client.registerDelegation(delegation)).rejects.toThrow(
        "validFrom must precede validUntil",
      );
    });

    it("throws when validFrom equals validUntil", async () => {
      const client = createClient("example.com");
      const delegation = validDelegation({
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2026-01-01T00:00:00Z",
      });

      await expect(client.registerDelegation(delegation)).rejects.toThrow(
        "validFrom must precede validUntil",
      );
    });

    it("passes valid delegation through to API", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const delegation = validDelegation({
        scope: { credentialTypes: ["UniversityDegreeCredential", "DiplomaCredential"], namespaces: ["education"] },
      });

      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: delegation,
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      const result = await client.registerDelegation(delegation);

      expect(api.publishRecord).toHaveBeenCalled();
      expect(result).toEqual(delegation);
    });
  });

  // ── resolveDelegation ────────────────────────────────────────────

  describe("resolveDelegation", () => {
    it("looks up delegation record by id", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const delegation = {
        id: "del-1",
        issuerDid: "did:key:issuer",
        delegateDid: "did:key:delegate",
        scope: { credentialTypes: ["UniversityDegreeCredential"], namespaces: ["education"] },
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2027-01-01T00:00:00Z",
        certificate: {},
      };

      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: delegation,
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      const result = await client.resolveDelegation("del-1");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        DELEGATION_REGISTRY,
        "del-1",
      );
      expect(result).toEqual(delegation);
    });

    it("throws when detail is null", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: null,
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.resolveDelegation("del-1")).rejects.toThrow(
        "Delegation detail is missing or not an object",
      );
    });

    it("throws when detail is missing required fields", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: { id: "del-1" },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.resolveDelegation("del-1")).rejects.toThrow(
        "Delegation detail missing required field",
      );
    });

    it("throws when scope is not an object", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: {
          id: "del-1",
          issuerDid: "did:key:issuer",
          delegateDid: "did:key:delegate",
          scope: "issue",
          validFrom: "2026-01-01T00:00:00Z",
          validUntil: "2027-01-01T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.resolveDelegation("del-1")).rejects.toThrow(
        "Delegation detail field 'scope' must be an object",
      );
    });

    it("throws when scope is an array instead of object", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: {
          id: "del-1",
          issuerDid: "did:key:issuer",
          delegateDid: "did:key:delegate",
          scope: ["issue"],
          validFrom: "2026-01-01T00:00:00Z",
          validUntil: "2027-01-01T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.resolveDelegation("del-1")).rejects.toThrow(
        "Delegation detail field 'scope' must be an object",
      );
    });

    it("throws when scope.credentialTypes is not an array", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: {
          id: "del-1",
          issuerDid: "did:key:issuer",
          delegateDid: "did:key:delegate",
          scope: { credentialTypes: "not-array", namespaces: [] },
          validFrom: "2026-01-01T00:00:00Z",
          validUntil: "2027-01-01T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.resolveDelegation("del-1")).rejects.toThrow(
        "Delegation scope field 'credentialTypes' must be an array",
      );
    });

    it("throws when scope.credentialTypes contains non-strings", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: {
          id: "del-1",
          issuerDid: "did:key:issuer",
          delegateDid: "did:key:delegate",
          scope: { credentialTypes: [123, true], namespaces: [] },
          validFrom: "2026-01-01T00:00:00Z",
          validUntil: "2027-01-01T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.resolveDelegation("del-1")).rejects.toThrow(
        "Delegation scope field 'credentialTypes' must contain only strings",
      );
    });

    it("throws when scope.namespaces contains non-strings", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "del-1",
        registry: DELEGATION_REGISTRY,
        namespace: "example.com",
        detail: {
          id: "del-1",
          issuerDid: "did:key:issuer",
          delegateDid: "did:key:delegate",
          scope: { credentialTypes: [], namespaces: [42] },
          validFrom: "2026-01-01T00:00:00Z",
          validUntil: "2027-01-01T00:00:00Z",
        },
        state: "live",
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      });

      await expect(client.resolveDelegation("del-1")).rejects.toThrow(
        "Delegation scope field 'namespaces' must contain only strings",
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
        tag: "revoke",
        state: "active",
        record_count: 0,
        created_at: "",
        updated_at: "",
      });

      await client.ensureRegistries("example.com");

      expect(api.createNamespace).toHaveBeenCalledWith(
        "example.com",
        expect.any(String),
      );
      expect(api.createRegistry).toHaveBeenCalledTimes(3);
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        REVOCATION_REGISTRY,
        expect.any(Object),
        "revoke",
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        expect.any(Object),
        "public_key",
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        SCHEMA_REGISTRY,
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
      await expect(
        client.ensureRegistries("example.com"),
      ).resolves.toBeUndefined();
    });

    it("re-throws non-409 errors", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.createNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 500", 502),
      );

      await expect(client.ensureRegistries("example.com")).rejects.toThrow(
        "DeDi API error: 500",
      );
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
        detail: { did: "did:web:example.com", document: didDocument, resolvedAt: "2026-03-25T00:00:00Z" },
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
      schemaId: "education",
      version: "1",
      schema: { type: "object", properties: {} },
      contextUrl: "https://opencred.dev/contexts/education/v1",
      checksum: "abc123",
      publishedAt: "2026-03-25T00:00:00Z",
    };

    it("publishes a schema to the schema_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        name: "education-v1",
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
        "education-v1",
        testSchema,
      );
      expect(result.published).toBe(true);
      expect(result.recordName).toBe("education-v1");
    });
  });

  // ── resolveSchema ────────────────────────────────────────────────

  describe("resolveSchema", () => {
    it("looks up a schema from the schema_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const schemaDetail: SchemaRecord = {
        schemaId: "education",
        version: "1",
        schema: { type: "object" },
        checksum: "abc",
        publishedAt: "2026-03-25T00:00:00Z",
      };
      vi.mocked(api.lookupRecord).mockResolvedValue({
        name: "education-v1",
        registry: SCHEMA_REGISTRY,
        namespace: "example.com",
        detail: schemaDetail,
        state: "live",
        version: 1,
        created_at: "",
        updated_at: "",
      });

      const result = await client.resolveSchema("education", "1");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        SCHEMA_REGISTRY,
        "education-v1",
      );
      expect(result.schemaId).toBe("education");
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
  });
});
