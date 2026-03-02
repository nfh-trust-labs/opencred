import { describe, it, expect, vi, beforeEach } from "vitest";
import { DeDiClientError } from "@opencred/shared";
import { DeDiClient } from "../adapter/client.js";
import { DeDiApiClient } from "../api/api-client.js";
import { REVOCATION_REGISTRY, DELEGATION_REGISTRY, PUBLIC_KEY_REGISTRY } from "../adapter/registry-names.js";

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
        detail: { hash: "abc", revoked: true, revokedAt: "2026-01-01T00:00:00Z" },
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
            detail: { hash: "abc", revoked: true, revokedAt: "2026-01-01T00:00:00Z" },
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

    it("returns { revoked: false } when registry does not exist (404)", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockRejectedValue(new DeDiClientError("DeDi API error: 404", 404));

      const result = await client.queryRevocationHash("missing");

      expect(result).toEqual({ hash: "missing", revoked: false });
    });
  });

  // ── registerDelegation ───────────────────────────────────────────

  describe("registerDelegation", () => {
    it("publishes delegation to delegation_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const delegation = {
        id: "del-1",
        issuerDid: "did:key:issuer",
        delegateDid: "did:key:delegate",
        scope: ["issue"],
        validFrom: "2026-01-01T00:00:00Z",
        validUntil: "2027-01-01T00:00:00Z",
        certificate: {},
      };

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

  // ── resolveDelegation ────────────────────────────────────────────

  describe("resolveDelegation", () => {
    it("looks up delegation record by id", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const delegation = {
        id: "del-1",
        issuerDid: "did:key:issuer",
        delegateDid: "did:key:delegate",
        scope: ["issue"],
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

      expect(api.createNamespace).toHaveBeenCalledWith("example.com", expect.any(String));
      expect(api.createRegistry).toHaveBeenCalledTimes(3);
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        REVOCATION_REGISTRY,
        expect.any(Object),
        "revoke",
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        DELEGATION_REGISTRY,
        expect.any(Object),
        "membership",
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        expect.any(Object),
        "public_key",
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
});
