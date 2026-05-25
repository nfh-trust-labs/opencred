import { describe, it, expect, vi, beforeEach } from "vitest";
import { DeDiClientError, DeDiRecordExistsError } from "@opencred/shared";
import { DeDiClient } from "../adapter/client.js";
import { DeDiApiClient } from "../api/api-client.js";
import type { ContextRecord, SchemaRecord } from "../adapter/types.js";
import type { DeDiProof } from "../api/types.js";
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
  MockDeDiApiClient.prototype.updateRecord = vi.fn();
  MockDeDiApiClient.prototype.search = vi.fn();
  MockDeDiApiClient.prototype.createNamespace = vi.fn();
  MockDeDiApiClient.prototype.createRegistry = vi.fn();
  MockDeDiApiClient.prototype.lookupNamespace = vi.fn();
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
      vi.mocked(api.lookupRecord).mockRejectedValue(new DeDiClientError("Record not found", 404));

      await client.queryRevocationHash("abc");

      expect(api.lookupRecord).toHaveBeenCalledWith("example.com", REVOCATION_REGISTRY, "abc");
    });

    it("uses explicit namespace over defaultNamespace", async () => {
      const client = createClient("default.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockRejectedValue(new DeDiClientError("Record not found", 404));

      await client.queryRevocationHash("abc", "explicit.com");

      expect(api.lookupRecord).toHaveBeenCalledWith("explicit.com", REVOCATION_REGISTRY, "abc");
    });

    it("throws when no namespace available", async () => {
      const client = createClient(); // no default
      await expect(client.queryRevocationHash("abc")).rejects.toThrow("No namespace provided");
    });
  });

  // ── publishRevocationHash ────────────────────────────────────────

  describe("publishRevocationHash", () => {
    it("publishes a record to the vc-revocation-registry using canonical revoke schema", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        message: "Record published",
        data: {
          record_name: "abc",
          registry: REVOCATION_REGISTRY,
          namespace: "example.com",
          details: { revoked_id: "abc" },
          state: "live",
          version: "1",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
      });

      const result = await client.publishRevocationHash("abc");

      // Payload must match https://dedi.global/revoke.json — `revoked_id`
      // is required, `reason` is omitted when not supplied.
      expect(api.publishRecord).toHaveBeenCalledWith("example.com", REVOCATION_REGISTRY, "abc", {
        revoked_id: "abc",
      });
      // Record existence ⇒ revoked; revokedAt comes from envelope.updated_at.
      expect(result).toEqual({ revoked: true, revokedAt: "2026-01-01T00:00:00Z" });
    });

    it("passes through optional reason in the payload and result", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        message: "Record published",
        data: {
          record_name: "abc",
          registry: REVOCATION_REGISTRY,
          namespace: "example.com",
          details: { revoked_id: "abc", reason: "Key compromised" },
          state: "live",
          version: "1",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
      });

      const result = await client.publishRevocationHash("abc", "example.com", "Key compromised");

      expect(api.publishRecord).toHaveBeenCalledWith("example.com", REVOCATION_REGISTRY, "abc", {
        revoked_id: "abc",
        reason: "Key compromised",
      });
      expect(result).toEqual({
        revoked: true,
        revokedAt: "2026-01-01T00:00:00Z",
        reason: "Key compromised",
      });
    });

    it("rewraps DeDi 409 duplicate-record as DeDiRecordExistsError with hint", async () => {
      // Real DeDi 409 body shape observed on api.dedi.global:
      //   { message: "duplicate record name",
      //     data: "Record with the same name already exists in the registry - vc-revocation-registry" }
      // The adapter must surface this as a specific error so HTTP clients
      // can distinguish "already revoked" (success-after-prior-run) from
      // generic DeDi failures. Regression guard for the bootcamp confusion
      // documented in docs/bootcamp/post-bootcamp-followups.md §6.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409, {
          message: "duplicate record name",
          data: "Record with the same name already exists in the registry - vc-revocation-registry",
        }),
      );

      await expect(client.publishRevocationHash("abc")).rejects.toBeInstanceOf(
        DeDiRecordExistsError,
      );
      try {
        await client.publishRevocationHash("abc");
      } catch (err) {
        expect(err).toBeInstanceOf(DeDiRecordExistsError);
        const recordExists = err as DeDiRecordExistsError;
        expect(recordExists.statusCode).toBe(409);
        expect(recordExists.code).toBe("DEDI_RECORD_EXISTS");
        expect(recordExists.hint).toContain("revocation-status");
        // Original DeDi response body is preserved for debugging.
        expect(recordExists.responseBody).toMatchObject({
          message: "duplicate record name",
        });
      }
    });

    it("rewraps duplicate-record signal carried only on data field (no message)", async () => {
      // Defensive: future DeDi wording may move the duplicate signal
      // entirely into `data`. Helper checks both fields.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409, {
          data: "Record with the same name already exists in the registry - vc-revocation-registry",
        }),
      );
      await expect(client.publishRevocationHash("abc")).rejects.toBeInstanceOf(
        DeDiRecordExistsError,
      );
    });

    it("rewraps duplicate-record signal carried as a raw string body", async () => {
      // Some DeDi error responses may surface as bare text rather than JSON.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409, "duplicate record name"),
      );
      await expect(client.publishRevocationHash("abc")).rejects.toBeInstanceOf(
        DeDiRecordExistsError,
      );
    });

    it("passes through non-duplicate 409s as the original DeDiClientError", async () => {
      // Not every 409 is a duplicate. A future "concurrent rotation"
      // conflict, for example, must NOT be silently reclassified.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409, {
          message: "version conflict",
          data: "Record version is stale; retry with current version",
        }),
      );
      await expect(client.publishRevocationHash("abc")).rejects.toBeInstanceOf(DeDiClientError);
      await expect(client.publishRevocationHash("abc")).rejects.not.toBeInstanceOf(
        DeDiRecordExistsError,
      );
    });

    it("passes through non-409 errors unchanged", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 500", 500, "internal server error"),
      );
      await expect(client.publishRevocationHash("abc")).rejects.toBeInstanceOf(DeDiClientError);
      await expect(client.publishRevocationHash("abc")).rejects.not.toBeInstanceOf(
        DeDiRecordExistsError,
      );
    });
  });

  // ── queryRevocationHash ──────────────────────────────────────────

  describe("queryRevocationHash", () => {
    it("looks up by record_name and reports revoked when present", async () => {
      // The hash IS the record_name (set by publishRevocationHash), so a
      // direct lookupRecord is correct and faster than search — and works
      // around the `details.revoked_id` filter being empty-on-arrival on
      // api.dedi.global. Regression guard for #610.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "abc",
          registry: REVOCATION_REGISTRY,
          namespace: "example.com",
          details: { revoked_id: "abc" },
          state: "live",
          version: "1",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-02T00:00:00Z",
        },
      });

      const result = await client.queryRevocationHash("abc");

      expect(api.lookupRecord).toHaveBeenCalledWith("example.com", REVOCATION_REGISTRY, "abc");
      expect(result).toEqual({ revoked: true, revokedAt: "2026-01-02T00:00:00Z" });
    });

    it("surfaces optional reason from the record details", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "abc",
          registry: REVOCATION_REGISTRY,
          namespace: "example.com",
          details: { revoked_id: "abc", reason: "Key compromised" },
          state: "live",
          version: "1",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-02T00:00:00Z",
        },
      });

      const result = await client.queryRevocationHash("abc");

      expect(result).toEqual({
        revoked: true,
        revokedAt: "2026-01-02T00:00:00Z",
        reason: "Key compromised",
      });
    });

    it("returns { revoked: false } when lookup returns 404", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockRejectedValue(new DeDiClientError("Record not found", 404));

      const result = await client.queryRevocationHash("missing");

      expect(result).toEqual({ revoked: false });
    });

    it("re-throws non-404 errors", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 500", 502),
      );

      await expect(client.queryRevocationHash("hash")).rejects.toThrow("DeDi API error: 500");
    });
  });

  // ── resolveDID ───────────────────────────────────────────────────

  describe("resolveDID", () => {
    it("looks up DID record in public_key_registry", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const didRecord = {
        did: "did:key:z6Mk123",
        keyStatus: "current" as const,
      };

      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: didRecord,
          state: "live",
          version: "1",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
      });

      const result = await client.resolveDID("did:key:z6Mk123");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        expect.any(String), // DID to record name conversion
      );
      expect(result).toEqual(didRecord);
    });

    it("returns did:web record with cached document", async () => {
      // did:web records DO carry document — it caches the domain-hosted
      // .well-known/did.json so the resolver fallback can serve it when
      // the issuer's webserver is unreachable.
      const client = createClient("example.com");
      const api = mockApi();
      const document = { id: "did:web:example.com", verificationMethod: [] };
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-example.com",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:web:example.com", document, keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.resolveDID("did:web:example.com");
      expect(result.did).toBe("did:web:example.com");
      expect(result.document).toEqual(document);
      expect(result.keyStatus).toBe("current");
    });

    it("returns rotated DID record with keyStatus 'rotated'", async () => {
      // Verifier UI surfaces a "Rotated" badge for credentials whose
      // issuer DID has been marked rotated in DeDi.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mkold",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mkold", keyStatus: "rotated" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.resolveDID("did:key:z6Mkold");
      expect(result.keyStatus).toBe("rotated");
    });

    it("converts DID colons to hyphens for record name", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mk123", keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await client.resolveDID("did:key:z6Mk123");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        "did-key-z6Mk123",
      );
    });

    it("throws when API returns invalid DID record (missing did)", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { invalid: true },
          state: "live",
          version: "1",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
      });

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DID record detail missing required field: did",
      );
    });

    it("throws when keyStatus is missing or not a valid enum value", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mk123", keyStatus: "wat" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DID record detail field 'keyStatus' must be 'current' or 'rotated'",
      );
    });

    it("throws when document is present but not an object", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mk123", keyStatus: "current", document: "not-an-object" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DID record detail field 'document' must be an object when present",
      );
    });

    it("surfaces the CORD anchor proof block when DeDi returns one", async () => {
      // The proof block lives on the envelope (sibling to `details`), not
      // inside `details`. The adapter copies it onto the returned record so
      // verifier code can read `record.proof` directly.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mk123", keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
          proof: {
            type: "DediRecordProof2026",
            namespace_did: "did:cord:ns:example",
            registry_identifier: "reg-public-key",
            record_identifier: "rec-did-key-z6Mk123",
            creator_did: "did:key:z6Mk123",
            digest: "abc123def456",
            network_genesis: "0xCordGenesis",
          },
        },
      });

      const result = await client.resolveDID("did:key:z6Mk123");
      expect(result.proof).toBeDefined();
      expect(result.proof?.creator_did).toBe("did:key:z6Mk123");
      expect(result.proof?.digest).toBe("abc123def456");
      expect(result.proof?.network_genesis).toBe("0xCordGenesis");
      expect(result.proof?.registry_identifier).toBe("reg-public-key");
      expect(result.proof?.record_identifier).toBe("rec-did-key-z6Mk123");
    });

    it("omits proof when DeDi envelope has no proof block", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mk123", keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.resolveDID("did:key:z6Mk123");
      expect(result.proof).toBeUndefined();
      expect(result.did).toBe("did:key:z6Mk123");
    });

    it("accepts a proof block with null network_genesis", async () => {
      // network_genesis is `string | null` on the wire — a record may exist
      // in DeDi without being anchored to a specific network yet. Accept
      // null and normalize to null in the returned proof.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mk123", keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
          proof: {
            type: "DediRecordProof2026",
            namespace_did: "did:cord:ns:example",
            creator_did: "did:key:z6Mk123",
            digest: "abc",
            network_genesis: null,
          },
        },
      });

      const result = await client.resolveDID("did:key:z6Mk123");
      expect(result.proof).toBeDefined();
      expect(result.proof?.network_genesis).toBeNull();
    });

    it("drops a malformed proof block instead of throwing", async () => {
      // A proof missing required fields (e.g. creator_did) is treated as
      // "no anchor info" rather than a server-side bug — historically DeDi
      // shipped envelopes without proof, and we don't want a flaky proof
      // shape to fail an otherwise-valid record lookup.
      const client = createClient("example.com");
      const api = mockApi();
      // Cast to `unknown` first to bypass DeDiProof's required-fields
      // typing — the whole point is to simulate a non-conforming server
      // response and confirm the adapter drops it silently rather than
      // throwing on the typing-narrowed path.
      const malformedProof = { type: "DediRecordProof2026" } as unknown as DeDiProof;
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mk123", keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
          proof: malformedProof,
        },
      });

      const result = await client.resolveDID("did:key:z6Mk123");
      expect(result.proof).toBeUndefined();
      expect(result.did).toBe("did:key:z6Mk123");
    });
  });

  // ── ensureRegistries ─────────────────────────────────────────────

  describe("ensureRegistries", () => {
    it("creates namespace and all three registries", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      // Lookup returns 404 first time, then create succeeds (the fresh-
      // install path — namespace doesn't exist yet, so create runs once).
      vi.mocked(api.lookupNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 404", 404),
      );
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

      expect(api.lookupNamespace).toHaveBeenCalledWith("example.com");
      expect(api.createNamespace).toHaveBeenCalledWith("example.com", expect.any(String));
      expect(api.createRegistry).toHaveBeenCalledTimes(4);
      // Revocation registry uses DeDi's canonical "Revoke" tag — the tag
      // drives server-side validation, so we pass no inline schema. The
      // string MUST be capital-R "Revoke"; lowercase is rejected with 400
      // by api.dedi.global (regression guard for #609).
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        REVOCATION_REGISTRY,
        {},
        "Revoke",
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        expect.objectContaining({
          properties: expect.objectContaining({
            did: { type: "string", pattern: "^did:" },
            keyStatus: { type: "string", enum: ["current", "rotated"] },
          }),
          required: ["did", "keyStatus"],
          additionalProperties: false,
        }),
      );
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        SCHEMA_REGISTRY,
        expect.objectContaining({
          properties: expect.objectContaining({ schemaId: { type: "string" } }),
        }),
      );
      // CONTEXT_REGISTRY uses an inline schema (no tag) because DeDi has
      // no no-schema "custom" tag — the previously-assumed "custom" was
      // rejected with 400 by api.dedi.global (regression guard for #609).
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        CONTEXT_REGISTRY,
        expect.objectContaining({
          properties: expect.objectContaining({ "@context": expect.any(Object) }),
          required: ["@context"],
          additionalProperties: true,
        }),
      );
    });

    it("skips createNamespace when lookupNamespace finds an existing namespace", async () => {
      // Issue #546 regression test: pre-existing namespace must not be
      // re-created. lookupNamespace returns 200, so createNamespace should
      // never be called.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupNamespace).mockResolvedValue({
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

      await expect(client.ensureRegistries("example.com")).resolves.toBeUndefined();

      expect(api.lookupNamespace).toHaveBeenCalledWith("example.com");
      expect(api.createNamespace).not.toHaveBeenCalled();
    });

    it("treats 409 Conflict on create as success (race after lookup)", async () => {
      // If the lookup returns 404 but a concurrent client creates the
      // namespace before our POST lands, the POST returns 409 — treat as
      // benign.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 404", 404),
      );
      vi.mocked(api.createNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409),
      );
      vi.mocked(api.createRegistry).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409),
      );

      await expect(client.ensureRegistries("example.com")).resolves.toBeUndefined();
    });

    it("treats body code NAMESPACE_EXISTS on create as success", async () => {
      // DeDi sometimes returns 400 with body code rather than 409.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 404", 404),
      );
      vi.mocked(api.createNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 400", 400, { code: "NAMESPACE_EXISTS" }),
      );
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

      await expect(client.ensureRegistries("example.com")).resolves.toBeUndefined();
    });

    it("re-throws non-404 errors from lookupNamespace", async () => {
      // A transient 5xx on lookup must NOT fall through to create — that
      // is exactly how duplicate namespaces were created before. Surface
      // the error so the user knows the operation failed.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 500", 502),
      );

      await expect(client.ensureRegistries("example.com")).rejects.toThrow("DeDi API error: 500");
      expect(api.createNamespace).not.toHaveBeenCalled();
    });

    it("re-throws non-409 errors on create when lookup said 404", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupNamespace).mockRejectedValue(
        new DeDiClientError("DeDi API error: 404", 404),
      );
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
    it("publishes a did:web record with document and keyStatus 'current'", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const didDocument = { id: "did:web:example.com", verificationMethod: [] };
      vi.mocked(api.publishRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-example.com",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:web:example.com", document: didDocument, keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.publishDID("did:web:example.com", didDocument);

      expect(api.publishRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        "did-web-example.com",
        {
          did: "did:web:example.com",
          document: didDocument,
          keyStatus: "current",
        },
      );
      expect(result.published).toBe(true);
      expect(result.recordName).toBe("did-web-example.com");
      expect(result.namespace).toBe("example.com");
    });

    it("publishes a did:key record WITHOUT document", async () => {
      // did:key records omit `document` — the verifier derives it from
      // the DID itself. Pin that even when the caller passes a document.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mkfoo",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mkfoo", keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await client.publishDID("did:key:z6Mkfoo", {
        id: "did:key:z6Mkfoo",
        verificationMethod: [],
      });

      expect(api.publishRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        "did-key-z6Mkfoo",
        // Document MUST NOT appear in the published detail for did:key.
        { did: "did:key:z6Mkfoo", keyStatus: "current" },
      );
    });

    it("rejects did:web records without a document", async () => {
      // The whole point of putting a did:web in DeDi is to cache the
      // domain-hosted document. Publishing without one is a programming
      // bug — surface it loudly with a 400.
      const client = createClient("example.com");
      await expect(client.publishDID("did:web:example.com", null)).rejects.toThrow(
        "publishDID: did:web records require a DID Document",
      );
      await expect(client.publishDID("did:web:example.com", undefined)).rejects.toThrow(
        "publishDID: did:web records require a DID Document",
      );
    });

    it("rewraps DeDi 409 duplicate-record as DeDiRecordExistsError with resolve hint", async () => {
      // public_key_registry uses the DID as record_name, so republishing
      // the same DID returns DeDi's "duplicate record name" 409. The adapter
      // must surface this as a specific error so the operator/UI knows the
      // DID is already in DeDi and they should use /v1/keys/resolve.
      // Regression guard for docs/bootcamp/post-bootcamp-followups.md §6.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409, {
          message: "duplicate record name",
          data: "Record with the same name already exists in the registry - public_key_registry",
        }),
      );

      await expect(client.publishDID("did:key:z6Mkfoo", undefined)).rejects.toBeInstanceOf(
        DeDiRecordExistsError,
      );
      try {
        await client.publishDID("did:key:z6Mkfoo", undefined);
      } catch (err) {
        expect(err).toBeInstanceOf(DeDiRecordExistsError);
        const recordExists = err as DeDiRecordExistsError;
        expect(recordExists.statusCode).toBe(409);
        expect(recordExists.code).toBe("DEDI_RECORD_EXISTS");
        expect(recordExists.hint).toContain("resolve");
        expect(recordExists.responseBody).toMatchObject({ message: "duplicate record name" });
      }
    });

    it("publishDID passes through non-duplicate 409s unchanged", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409, {
          message: "version conflict",
        }),
      );
      await expect(client.publishDID("did:key:z6Mkfoo", undefined)).rejects.toBeInstanceOf(
        DeDiClientError,
      );
      await expect(client.publishDID("did:key:z6Mkfoo", undefined)).rejects.not.toBeInstanceOf(
        DeDiRecordExistsError,
      );
    });
  });

  // ── markDIDRotated ───────────────────────────────────────────────

  describe("markDIDRotated", () => {
    it("flips keyStatus from 'current' to 'rotated' via update-record", async () => {
      // Two API calls: a lookupRecord first (to preserve `did` + the
      // optional `document` so the wholesale-replace updateRecord doesn't
      // wipe them), then an updateRecord with the rotated payload.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mkold",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mkold", keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });
      vi.mocked(api.updateRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mkold",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mkold", keyStatus: "rotated" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await client.markDIDRotated("did:key:z6Mkold");

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        "did-key-z6Mkold",
      );
      expect(api.updateRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        "did-key-z6Mkold",
        { did: "did:key:z6Mkold", keyStatus: "rotated" },
      );
    });

    it("is a no-op for did:web — rotation lives inside verificationMethod[] now (issue #627)", async () => {
      // Per docs/spikes/spike-619-did-web-rotation.md, did:web rotation is
      // per-key inside the DID Document (handled by rotateDIDWeb), NOT a
      // whole-record keyStatus flip. markDIDRotated for did:web therefore
      // becomes a record-level no-op: no lookupRecord, no updateRecord,
      // just a warn log so callers who mis-routed here see the misuse.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({} as never);
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      await client.markDIDRotated("did:web:acme.com");

      expect(api.lookupRecord).not.toHaveBeenCalled();
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("propagates 404 when the record does not exist", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 404", 404),
      );

      await expect(client.markDIDRotated("did:key:z6Mkmissing")).rejects.toThrow(DeDiClientError);
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("is idempotent — skips update-record when already rotated", async () => {
      // Closes the concurrent-rotation window without an If-Match on
      // DeDi: the second caller's lookup sees `rotated` and short-circuits
      // before issuing the racy update-record write.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mkalready",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:key:z6Mkalready", keyStatus: "rotated" },
          state: "live",
          version: "2",
          created_at: "",
          updated_at: "",
        },
      });

      await client.markDIDRotated("did:key:z6Mkalready");

      expect(api.lookupRecord).toHaveBeenCalledTimes(1);
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("uses an explicit namespace override when provided", async () => {
      const client = createClient("default-ns");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mkfoo",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "other-ns",
          details: { did: "did:key:z6Mkfoo", keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      await client.markDIDRotated("did:key:z6Mkfoo", "other-ns");
      expect(api.lookupRecord).toHaveBeenCalledWith(
        "other-ns",
        PUBLIC_KEY_REGISTRY,
        expect.any(String),
      );
      expect(api.updateRecord).toHaveBeenCalledWith(
        "other-ns",
        PUBLIC_KEY_REGISTRY,
        "did-key-z6Mkfoo",
        expect.objectContaining({ keyStatus: "rotated" }),
      );
    });
  });

  // ── rotateDIDWeb ─────────────────────────────────────────────────
  // See docs/spikes/spike-619-did-web-rotation.md for the design these
  // tests pin down.

  describe("rotateDIDWeb", () => {
    const did = "did:web:acme.com";
    const oldJwk = { kty: "EC", crv: "P-256", x: "x-old", y: "y-old" };
    const newJwk = { kty: "EC", crv: "P-256", x: "x-new", y: "y-new" };

    function mockLookupReturnsDocWithVms(
      api: InstanceType<typeof DeDiApiClient>,
      vms: Record<string, unknown>[],
    ) {
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-acme.com",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: {
            did,
            document: {
              "@context": ["https://www.w3.org/ns/did/v1"],
              id: did,
              verificationMethod: vms,
              assertionMethod: [vms[vms.length - 1]?.["id"]],
            },
            keyStatus: "current",
          },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });
    }

    it("appends a new VM, marks the prior current key superseded, points assertionMethod at the new key", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      mockLookupReturnsDocWithVms(api, [
        {
          id: `${did}#key-1`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: oldJwk,
        },
      ]);
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.rotateDIDWeb(did, newJwk);

      expect(result.rotated).toBe(true);
      if (result.rotated) {
        expect(result.did).toBe(did);
        expect(result.currentKeyId).toBe(`${did}#key-2`);
        expect(result.superseded).toEqual([`${did}#key-1`]);
        expect(result.namespace).toBe("example.com");
      }

      expect(api.updateRecord).toHaveBeenCalledTimes(1);
      const writeCall = vi.mocked(api.updateRecord).mock.calls[0]!;
      expect(writeCall[0]).toBe("example.com");
      expect(writeCall[1]).toBe(PUBLIC_KEY_REGISTRY);
      expect(writeCall[2]).toBe("did-web-acme.com");
      const written = writeCall[3] as {
        did: string;
        document: {
          verificationMethod: Record<string, unknown>[];
          assertionMethod: string[];
        };
        keyStatus: string;
      };
      // Two VM entries now: old (with supersededAt) + new (no supersededAt)
      expect(written.document.verificationMethod).toHaveLength(2);
      expect(written.document.verificationMethod[0]).toMatchObject({
        id: `${did}#key-1`,
        publicKeyJwk: oldJwk,
        supersededAt: expect.any(String),
      });
      expect(written.document.verificationMethod[1]).toMatchObject({
        id: `${did}#key-2`,
        publicKeyJwk: newJwk,
      });
      expect(written.document.verificationMethod[1]).not.toHaveProperty("supersededAt");
      // assertionMethod points at the NEW key only
      expect(written.document.assertionMethod).toEqual([`${did}#key-2`]);
      // keyStatus stays "current" — did:web rotation does NOT flip
      // the parent record's status (per spike §6).
      expect(written.keyStatus).toBe("current");
    });

    it("idempotent short-circuit: returns {rotated:false} without writing when the active key already matches the latest VM", async () => {
      // The exact same JWK is in the document already — re-running
      // rotate is a no-op (no DeDi version bump, no warn-log noise).
      const client = createClient("example.com");
      const api = mockApi();
      mockLookupReturnsDocWithVms(api, [
        {
          id: `${did}#key-1`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: newJwk,
        },
      ]);
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.rotateDIDWeb(did, newJwk);

      expect(result.rotated).toBe(false);
      if (!result.rotated) {
        expect(result.did).toBe(did);
        expect(result.currentKeyId).toBe(`${did}#key-1`);
        expect(result.reason).toBe("already-current");
      }
      // No write issued
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("idempotent short-circuit handles JWK property order (canonicalised comparison)", async () => {
      // Same key, different property order — the canonicalised
      // comparison must treat them as equal.
      const client = createClient("example.com");
      const api = mockApi();
      const storedJwk = { y: "y-new", x: "x-new", crv: "P-256", kty: "EC" };
      const incomingJwk = { kty: "EC", crv: "P-256", x: "x-new", y: "y-new" };
      mockLookupReturnsDocWithVms(api, [
        {
          id: `${did}#key-1`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: storedJwk,
        },
      ]);

      const result = await client.rotateDIDWeb(did, incomingJwk);

      expect(result.rotated).toBe(false);
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("computes next fragment counter from the max existing #key-N", async () => {
      // Document has key-1 (superseded), key-5 (current). Next should
      // be key-6 — we pick max+1, not count+1, to tolerate gaps.
      const client = createClient("example.com");
      const api = mockApi();
      mockLookupReturnsDocWithVms(api, [
        {
          id: `${did}#key-1`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: { kty: "EC", crv: "P-256", x: "x1", y: "y1" },
          supersededAt: "2025-01-01T00:00:00Z",
        },
        {
          id: `${did}#key-5`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: oldJwk,
        },
      ]);
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.rotateDIDWeb(did, newJwk);

      expect(result.rotated).toBe(true);
      if (result.rotated) {
        expect(result.currentKeyId).toBe(`${did}#key-6`);
        // Only #key-5 was un-superseded going in, so only it is
        // newly marked superseded.
        expect(result.superseded).toEqual([`${did}#key-5`]);
      }
    });

    it("rejects did:key with 400 KEY_METHOD_MISMATCH-style DeDiClientError", async () => {
      const client = createClient("example.com");
      await expect(client.rotateDIDWeb("did:key:z6MkAbc", newJwk)).rejects.toThrow(DeDiClientError);
      await expect(client.rotateDIDWeb("did:key:z6MkAbc", newJwk)).rejects.toThrow(
        /only did:web rotation is supported/,
      );
    });

    it("propagates 404 when the DID has no existing DeDi record", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 404", 404),
      );
      await expect(client.rotateDIDWeb(did, newJwk)).rejects.toThrow(DeDiClientError);
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("rejects an existing record that has no document (502)", async () => {
      // Shouldn't happen in practice — did:web records always carry a
      // document — but if it does, fail closed rather than silently
      // create a `verificationMethod` array out of thin air.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-acme.com",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          // No document — shape-asserter still passes since document is
          // optional on DIDRecord.
          details: { did, keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });
      await expect(client.rotateDIDWeb(did, newJwk)).rejects.toThrow(/has no document/);
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("uses an explicit namespace override when provided", async () => {
      const client = createClient("default-ns");
      const api = mockApi();
      mockLookupReturnsDocWithVms(api, [
        {
          id: `${did}#key-1`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: oldJwk,
        },
      ]);
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.rotateDIDWeb(did, newJwk, "explicit-ns");

      expect(result.rotated).toBe(true);
      expect(api.lookupRecord).toHaveBeenCalledWith(
        "explicit-ns",
        PUBLIC_KEY_REGISTRY,
        "did-web-acme.com",
      );
      expect(api.updateRecord).toHaveBeenCalledWith(
        "explicit-ns",
        PUBLIC_KEY_REGISTRY,
        "did-web-acme.com",
        expect.any(Object),
      );
    });

    it("multi-call sequence: rotate twice produces 3 VMs with 2 superseded", async () => {
      // The first rotation produces a 2-key doc. Re-running rotate
      // with yet another key against that doc should append #key-3 and
      // mark only the most-recent un-superseded entry (#key-2) as
      // superseded; #key-1 stays superseded with its original
      // timestamp (preserved, not re-stamped).
      const client = createClient("example.com");
      const api = mockApi();
      const key3Jwk = { kty: "EC", crv: "P-256", x: "x-3", y: "y-3" };
      mockLookupReturnsDocWithVms(api, [
        {
          id: `${did}#key-1`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: oldJwk,
          supersededAt: "2025-01-01T00:00:00Z",
        },
        {
          id: `${did}#key-2`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: newJwk,
        },
      ]);
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      await client.rotateDIDWeb(did, key3Jwk);

      const written = vi.mocked(api.updateRecord).mock.calls[0]![3] as {
        document: { verificationMethod: Record<string, unknown>[] };
      };
      expect(written.document.verificationMethod).toHaveLength(3);
      // key-1 superseded timestamp preserved exactly
      expect(written.document.verificationMethod[0]).toMatchObject({
        id: `${did}#key-1`,
        supersededAt: "2025-01-01T00:00:00Z",
      });
      // key-2 newly superseded
      expect(written.document.verificationMethod[1]).toMatchObject({
        id: `${did}#key-2`,
      });
      expect(written.document.verificationMethod[1]).toHaveProperty("supersededAt");
      expect(written.document.verificationMethod[1]!["supersededAt"]).not.toBe(
        "2025-01-01T00:00:00Z",
      );
      // key-3 is the new current key, no supersededAt
      expect(written.document.verificationMethod[2]).toMatchObject({
        id: `${did}#key-3`,
        publicKeyJwk: key3Jwk,
      });
      expect(written.document.verificationMethod[2]).not.toHaveProperty("supersededAt");
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
        message: "ok",
        data: {
          record_name: "functional-identity-v1",
          registry: SCHEMA_REGISTRY,
          namespace: "example.com",
          details: testSchema,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
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
        message: "ok",
        data: {
          record_name: "functional-identity-v1",
          registry: SCHEMA_REGISTRY,
          namespace: "example.com",
          details: schemaDetail,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
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
        message: "ok",
        data: {
          record_name: "bad-v1",
          registry: SCHEMA_REGISTRY,
          namespace: "example.com",
          details: { schemaId: "bad" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveSchema("bad", "1")).rejects.toThrow(
        "Schema record detail missing required field",
      );
    });

    it("throws when checksum is not a string", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "test-v1",
          registry: SCHEMA_REGISTRY,
          namespace: "example.com",
          details: {
            schemaId: "test",
            version: "1",
            schema: { type: "object" },
            checksum: 12345,
            publishedAt: "2026-01-01T00:00:00Z",
          },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveSchema("test", "1")).rejects.toThrow(
        "Schema record field 'checksum' must be a string",
      );
    });

    it("throws when publishedAt is not a string", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "test-v1",
          registry: SCHEMA_REGISTRY,
          namespace: "example.com",
          details: {
            schemaId: "test",
            version: "1",
            schema: { type: "object" },
            checksum: "abc",
            publishedAt: null,
          },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveSchema("test", "1")).rejects.toThrow(
        "Schema record field 'publishedAt' must be a string",
      );
    });

    it("surfaces the CORD anchor proof on schema records", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "test-v1",
          registry: SCHEMA_REGISTRY,
          namespace: "example.com",
          details: {
            schemaId: "test",
            version: "1",
            schema: { type: "object" },
            checksum: "abc",
            publishedAt: "2026-01-01T00:00:00Z",
          },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
          proof: {
            type: "DediRecordProof2026",
            namespace_did: "did:cord:ns:example",
            creator_did: "did:key:z6Mkfoo",
            digest: "schemaDigest",
            network_genesis: "0xCordGenesis",
          },
        },
      });

      const result = await client.resolveSchema("test", "1");
      expect(result.proof?.creator_did).toBe("did:key:z6Mkfoo");
      expect(result.proof?.digest).toBe("schemaDigest");
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
        message: "ok",
        data: {
          record_name: "functional-identity-ctx-v1",
          registry: CONTEXT_REGISTRY,
          namespace: "example.com",
          details: contextDetail,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
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
        message: "ok",
        data: {
          record_name: "bad-ctx-v1",
          registry: CONTEXT_REGISTRY,
          namespace: "example.com",
          details: { schemaId: "bad" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveContext("bad", "1")).rejects.toThrow(
        "Context record detail missing required field",
      );
    });

    it("throws when publishedAt is not a string", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "test-ctx-v1",
          registry: CONTEXT_REGISTRY,
          namespace: "example.com",
          details: {
            schemaId: "test",
            version: "1",
            context: { "@context": {} },
            publishedAt: 12345,
          },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveContext("test", "1")).rejects.toThrow(
        "Context record field 'publishedAt' must be a string",
      );
    });

    it("throws when context is not an object", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "test-ctx-v1",
          registry: CONTEXT_REGISTRY,
          namespace: "example.com",
          details: {
            schemaId: "test",
            version: "1",
            context: "not-an-object",
            publishedAt: "2026-01-01T00:00:00Z",
          },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveContext("test", "1")).rejects.toThrow(
        "Context record field 'context' must be an object",
      );
    });
  });

  // ── DeDi record wrapper validation ──────────────────────────────

  describe("DeDi record wrapper validation", () => {
    it("throws when lookupRecord returns response without details field", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: { record_name: "test" },
      } as never);

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DeDi API lookupRecord data response missing required field: details",
      );
    });

    it("throws when lookupRecord returns response without record_name field", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: { details: { did: "did:key:z6Mk123", keyStatus: "current" } },
      } as never);

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DeDi API lookupRecord data response missing required field: record_name",
      );
    });

    it("throws when lookupRecord returns response without data field", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
      } as never);

      await expect(client.resolveDID("did:key:z6Mk123")).rejects.toThrow(
        "DeDi API lookupRecord response missing required field: data",
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

  // ── Lookup result wrapper validation ────────────────────────────

  describe("lookup result wrapper validation", () => {
    it("throws when lookup returns envelope without data field", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({ message: "ok" } as never);

      await expect(client.queryRevocationHash("abc")).rejects.toThrow(
        "DeDi API lookupRecord response missing required field: data",
      );
    });

    it("throws when lookup returns null", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue(null as never);

      await expect(client.queryRevocationHash("abc")).rejects.toThrow(
        "DeDi API lookupRecord response is missing or not an object",
      );
    });
  });
});
