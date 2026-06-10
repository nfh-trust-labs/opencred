import { describe, it, expect, vi, beforeEach } from "vitest";
import { DeDiClientError, DeDiRecordExistsError } from "@opencred/shared";
import { DeDiClient } from "../adapter/client.js";
import { DeDiApiClient } from "../api/api-client.js";
import type { ContextRecord, KeyRecord, SchemaRecord } from "../adapter/types.js";
import type { DeDiProof } from "../api/types.js";
import {
  REVOCATION_REGISTRY,
  OPENCRED_KEY_REGISTRY,
  SCHEMA_REGISTRY,
  CONTEXT_REGISTRY,
} from "../adapter/registry-names.js";

// Mock the DeDiApiClient
vi.mock("../api/api-client.js", () => {
  const MockDeDiApiClient = vi.fn();
  MockDeDiApiClient.prototype.publishRecord = vi.fn();
  MockDeDiApiClient.prototype.lookupRecord = vi.fn();
  MockDeDiApiClient.prototype.updateRecord = vi.fn();
  MockDeDiApiClient.prototype.queryRecords = vi.fn();
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

  // ── resolveKey ───────────────────────────────────────────────────

  describe("resolveKey", () => {
    // A canonical per-key registry payload. The verification method
    // `did:key:z6Mk123#z6Mk123` slugifies to record name
    // `did-key-z6Mk123-z6Mk123`.
    const vm = "did:key:z6Mk123#z6Mk123";
    const recordName = "did-key-z6Mk123-z6Mk123";
    const keyDetail: KeyRecord = {
      keyId: vm,
      controllerDid: "did:key:z6Mk123",
      algorithm: "Ed25519",
      publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
      purpose: ["assertionMethod"],
      status: "active",
    };

    it("looks up the key record in opencred-key-registry by verification method", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyDetail,
          state: "live",
          version: "1",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
      });

      const result = await client.resolveKey(vm);

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        OPENCRED_KEY_REGISTRY,
        recordName,
      );
      expect(result).toEqual(keyDetail);
    });

    it("logs the DeDi envelope version at debug (positions OCC, #659)", async () => {
      // resolveKey surfaces the wire `version` so setKeyStatus can adopt a
      // conditional update later. Only the public verification-method id and
      // status are logged — never key material.
      const logger = { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() };
      const client = new DeDiClient({
        baseUrl: "https://dedi.example.com",
        timeoutMs: 5000,
        maxRetries: 0,
        circuitBreakerThreshold: 5,
        auth: { type: "api-key", apiKey: "dk_test" },
        defaultNamespace: "example.com",
        logger,
      });
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyDetail,
          state: "live",
          version: "7",
          created_at: "",
          updated_at: "",
        },
      });

      await client.resolveKey(vm);

      expect(logger.debug).toHaveBeenCalledWith(
        "Resolved key record",
        expect.objectContaining({ version: "7", status: "active", keyId: vm }),
      );
    });

    it("returns a rotated key record with status 'rotated'", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: { ...keyDetail, status: "rotated" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.resolveKey(vm);
      expect(result.status).toBe("rotated");
    });

    it("converts verification-method colons and # to hyphens for the record name", async () => {
      // `did:web:acme.com#key-0` → record name `did-web-acme.com-key-0`.
      const client = createClient("example.com");
      const api = mockApi();
      const webVm = "did:web:acme.com#key-0";
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-acme.com-key-0",
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: {
            keyId: webVm,
            controllerDid: "did:web:acme.com",
            algorithm: "ES256",
            publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
            purpose: ["assertionMethod"],
            status: "active",
          },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await client.resolveKey(webVm);

      expect(api.lookupRecord).toHaveBeenCalledWith(
        "example.com",
        OPENCRED_KEY_REGISTRY,
        "did-web-acme.com-key-0",
      );
    });

    it("throws when a required field is missing (keyId)", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: { invalid: true },
          state: "live",
          version: "1",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
      });

      await expect(client.resolveKey(vm)).rejects.toThrow(
        "Key record detail missing required field: keyId",
      );
    });

    it("throws when status is not a valid enum value", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: { ...keyDetail, status: "wat" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveKey(vm)).rejects.toThrow(
        "Key record detail field 'status' must be 'active', 'rotated', or 'revoked'",
      );
    });

    it("throws when publicKeyJwk is not an object", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: { ...keyDetail, publicKeyJwk: "not-an-object" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveKey(vm)).rejects.toThrow(
        "Key record detail field 'publicKeyJwk' must be an object",
      );
    });

    it("throws when purpose is not an array of strings", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: { ...keyDetail, purpose: [123] },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await expect(client.resolveKey(vm)).rejects.toThrow(
        "Key record detail field 'purpose' must be an array of strings",
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
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyDetail,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
          proof: {
            type: "DediRecordProof2026",
            namespace_did: "did:cord:ns:example",
            registry_identifier: "reg-opencred-key",
            record_identifier: "rec-did-key-z6Mk123",
            creator_did: "did:key:z6Mk123",
            digest: "abc123def456",
            network_genesis: "0xCordGenesis",
          },
        },
      });

      const result = await client.resolveKey(vm);
      expect(result.proof).toBeDefined();
      expect(result.proof?.creator_did).toBe("did:key:z6Mk123");
      expect(result.proof?.digest).toBe("abc123def456");
      expect(result.proof?.network_genesis).toBe("0xCordGenesis");
      expect(result.proof?.registry_identifier).toBe("reg-opencred-key");
      expect(result.proof?.record_identifier).toBe("rec-did-key-z6Mk123");
    });

    it("omits proof when DeDi envelope has no proof block", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyDetail,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.resolveKey(vm);
      expect(result.proof).toBeUndefined();
      expect(result.keyId).toBe(vm);
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
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyDetail,
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

      const result = await client.resolveKey(vm);
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
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyDetail,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
          proof: malformedProof,
        },
      });

      const result = await client.resolveKey(vm);
      expect(result.proof).toBeUndefined();
      expect(result.keyId).toBe(vm);
    });
  });

  // ── ensureRegistries ─────────────────────────────────────────────

  describe("ensureRegistries", () => {
    it("creates namespace and all five registries", async () => {
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
      // 4 registries: revocation, opencred-key, schema, context. (The
      // did-documents registry was removed in #670 — the did.json snapshot
      // now rides on each key record in opencred-key-registry.)
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
      // Per-key registry: one record per signing key. Inline schema, all six
      // fields required, additionalProperties:false.
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        OPENCRED_KEY_REGISTRY,
        expect.objectContaining({
          properties: expect.objectContaining({
            keyId: { type: "string", pattern: "^did:" },
            controllerDid: { type: "string", pattern: "^did:" },
            algorithm: { type: "string" },
            publicKeyJwk: { type: "object", description: "Public key material as a JWK." },
            purpose: { type: "array", items: { type: "string" } },
            status: { type: "string", enum: ["active", "rotated", "revoked"] },
          }),
          required: ["keyId", "controllerDid", "algorithm", "publicKeyJwk", "purpose", "status"],
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

  // ── publishKey ───────────────────────────────────────────────────

  describe("publishKey", () => {
    const keyRecord: KeyRecord = {
      keyId: "did:web:example.com#key-0",
      controllerDid: "did:web:example.com",
      algorithm: "ES256",
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
      purpose: ["assertionMethod"],
      status: "active",
    };

    it("publishes the key into opencred-key-registry keyed by the verification method", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-example.com-key-0",
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyRecord,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.publishKey(keyRecord);

      // record_name slugifies the verification method (`:`/`#` → `-`).
      // Published details are exactly the six fields — never the proof.
      expect(api.publishRecord).toHaveBeenCalledWith(
        "example.com",
        OPENCRED_KEY_REGISTRY,
        "did-web-example.com-key-0",
        {
          keyId: "did:web:example.com#key-0",
          controllerDid: "did:web:example.com",
          algorithm: "ES256",
          publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
          purpose: ["assertionMethod"],
          status: "active",
        },
      );
      expect(result.published).toBe(true);
      expect(result.recordName).toBe("did-web-example.com-key-0");
      expect(result.namespace).toBe("example.com");
    });

    it("strips any server-set proof from the published details", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-example.com-key-0",
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyRecord,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      await client.publishKey({
        ...keyRecord,
        proof: {
          type: "DediRecordProof2026",
          namespace_did: "did:cord:ns:example",
          creator_did: "did:web:example.com",
          digest: "abc",
          network_genesis: null,
        },
      });

      const publishedDetails = vi.mocked(api.publishRecord).mock.calls[0]![3] as Record<
        string,
        unknown
      >;
      expect(publishedDetails).not.toHaveProperty("proof");
    });

    it("slugifies a did:key verification method for the record name", async () => {
      // `did:key:z6Mk123#z6Mk123` → record name `did-key-z6Mk123-z6Mk123`.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-key-z6Mk123-z6Mk123",
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: keyRecord,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.publishKey({
        ...keyRecord,
        keyId: "did:key:z6Mk123#z6Mk123",
        controllerDid: "did:key:z6Mk123",
      });

      expect(api.publishRecord).toHaveBeenCalledWith(
        "example.com",
        OPENCRED_KEY_REGISTRY,
        "did-key-z6Mk123-z6Mk123",
        expect.objectContaining({ keyId: "did:key:z6Mk123#z6Mk123" }),
      );
      expect(result.recordName).toBe("did-key-z6Mk123-z6Mk123");
    });

    it("rewraps DeDi 409 duplicate-record as DeDiRecordExistsError with resolve hint", async () => {
      // Key records are immutable except for `status`, so republishing the
      // same key returns DeDi's "duplicate record name" 409. The adapter
      // surfaces this as a specific error so the operator/UI knows the key
      // is already in DeDi and they should use /v1/keys/resolve.
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409, {
          message: "duplicate record name",
          data: "Record with the same name already exists in the registry - opencred-key-registry",
        }),
      );

      await expect(client.publishKey(keyRecord)).rejects.toBeInstanceOf(DeDiRecordExistsError);
      try {
        await client.publishKey(keyRecord);
      } catch (err) {
        expect(err).toBeInstanceOf(DeDiRecordExistsError);
        const recordExists = err as DeDiRecordExistsError;
        expect(recordExists.statusCode).toBe(409);
        expect(recordExists.code).toBe("DEDI_RECORD_EXISTS");
        expect(recordExists.hint).toContain("resolve");
        expect(recordExists.responseBody).toMatchObject({ message: "duplicate record name" });
      }
    });

    it("passes through non-duplicate 409s unchanged", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 409", 409, {
          message: "version conflict",
        }),
      );
      await expect(client.publishKey(keyRecord)).rejects.toBeInstanceOf(DeDiClientError);
      await expect(client.publishKey(keyRecord)).rejects.not.toBeInstanceOf(DeDiRecordExistsError);
    });

    it("uses an explicit namespace override when provided", async () => {
      const client = createClient("default-ns");
      const api = mockApi();
      vi.mocked(api.publishRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-example.com-key-0",
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "other-ns",
          details: keyRecord,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });

      const result = await client.publishKey(keyRecord, "other-ns");
      expect(api.publishRecord).toHaveBeenCalledWith(
        "other-ns",
        OPENCRED_KEY_REGISTRY,
        "did-web-example.com-key-0",
        expect.any(Object),
      );
      expect(result.namespace).toBe("other-ns");
    });
  });

  // ── setKeyStatus ─────────────────────────────────────────────────
  // Monotone transition: active(0) → rotated(1) → revoked(2). Forward
  // moves write via update-record; same-rank / backward moves are no-ops.

  describe("setKeyStatus", () => {
    const vm = "did:web:acme.com#key-0";
    const recordName = "did-web-acme.com-key-0";
    function existingKey(status: "active" | "rotated" | "revoked"): KeyRecord {
      return {
        keyId: vm,
        controllerDid: "did:web:acme.com",
        algorithm: "ES256",
        publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
        purpose: ["assertionMethod"],
        status,
      };
    }
    function mockResolveKey(
      api: InstanceType<typeof DeDiApiClient>,
      status: "active" | "rotated" | "revoked",
    ) {
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: existingKey(status),
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });
    }

    it("advances active → revoked via update-record and returns changed:true", async () => {
      // Forward move (rank 0 → 2): reads the existing record, then writes
      // back the six fields with the new status.
      const client = createClient("example.com");
      const api = mockApi();
      mockResolveKey(api, "active");
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.setKeyStatus(vm, "revoked");

      expect(result).toEqual({
        changed: true,
        keyId: vm,
        from: "active",
        to: "revoked",
        namespace: "example.com",
      });
      expect(api.updateRecord).toHaveBeenCalledWith(
        "example.com",
        OPENCRED_KEY_REGISTRY,
        recordName,
        {
          keyId: vm,
          controllerDid: "did:web:acme.com",
          algorithm: "ES256",
          publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
          purpose: ["assertionMethod"],
          status: "revoked",
        },
      );
    });

    it("advances active → rotated via update-record", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      mockResolveKey(api, "active");
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.setKeyStatus(vm, "rotated");

      expect(result).toMatchObject({ changed: true, from: "active", to: "rotated" });
      expect(api.updateRecord).toHaveBeenCalledWith(
        "example.com",
        OPENCRED_KEY_REGISTRY,
        recordName,
        expect.objectContaining({ status: "rotated" }),
      );
    });

    it("is a no-op when the key is already at the requested status (already-at-status)", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      mockResolveKey(api, "rotated");
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.setKeyStatus(vm, "rotated");

      expect(result).toEqual({
        changed: false,
        keyId: vm,
        status: "rotated",
        reason: "already-at-status",
        namespace: "example.com",
      });
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("refuses to move the status backward (monotone-refused)", async () => {
      // revoked(2) → rotated(1) is a backward move — refused without a write.
      const client = createClient("example.com");
      const api = mockApi();
      mockResolveKey(api, "revoked");
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.setKeyStatus(vm, "rotated");

      expect(result).toEqual({
        changed: false,
        keyId: vm,
        status: "revoked",
        reason: "monotone-refused",
        namespace: "example.com",
      });
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("propagates 404 from resolveKey when the key has no record yet", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockRejectedValue(
        new DeDiClientError("DeDi API error: 404", 404),
      );

      await expect(client.setKeyStatus(vm, "revoked")).rejects.toThrow(DeDiClientError);
      expect(api.updateRecord).not.toHaveBeenCalled();
    });

    it("uses an explicit namespace override for both the read and the write", async () => {
      const client = createClient("default-ns");
      const api = mockApi();
      mockResolveKey(api, "active");
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      const result = await client.setKeyStatus(vm, "revoked", "other-ns");

      expect(result).toMatchObject({ changed: true, namespace: "other-ns" });
      expect(api.lookupRecord).toHaveBeenCalledWith("other-ns", OPENCRED_KEY_REGISTRY, recordName);
      expect(api.updateRecord).toHaveBeenCalledWith(
        "other-ns",
        OPENCRED_KEY_REGISTRY,
        recordName,
        expect.objectContaining({ status: "revoked" }),
      );
    });

    it("sequential rotate-then-revoke ends at revoked; revoked is terminal (#659)", async () => {
      // Causally-ordered rotate then revoke — the realistic operator path. A
      // stateful mock models DeDi's last-writer-wins `update-record`: each call
      // reads the previous write, so the rank guard advances
      // active → rotated → revoked. Once any writer has *observed* `revoked`,
      // the guard refuses every backward move, so a late stale rotate cannot
      // un-revoke it: revoked is terminal.
      //
      // What this does NOT exercise (deliberately, to avoid asserting a
      // guarantee the design doesn't give): the residual lost-update window
      // where two writers BOTH read the *same* pre-revoke state and race their
      // blind writes — last-writer-wins could then drop the revoke. That window
      // is what an Option-A CAS/version token closes; see the OCC note at the
      // `updateRecord` call. The guard only protects a writer that has already
      // observed the higher state.
      const client = createClient("example.com");
      const api = mockApi();
      let state: "active" | "rotated" | "revoked" = "active";
      vi.mocked(api.lookupRecord).mockImplementation((() =>
        Promise.resolve({
          message: "ok",
          data: {
            record_name: recordName,
            registry: OPENCRED_KEY_REGISTRY,
            namespace: "example.com",
            details: existingKey(state),
            state: "live",
            version: "1",
            created_at: "",
            updated_at: "",
          },
        })) as never);
      vi.mocked(api.updateRecord).mockImplementation(((...callArgs: unknown[]) => {
        // DeDi is last-writer-wins; record the status the write carried.
        state = (callArgs[3] as { status: typeof state }).status;
        return Promise.resolve({});
      }) as never);

      await client.setKeyStatus(vm, "rotated");
      expect(state).toBe("rotated");

      await client.setKeyStatus(vm, "revoked");
      expect(state).toBe("revoked");
      expect(api.updateRecord).toHaveBeenCalledTimes(2);

      // A late stale rotate reads the revoked record and is refused — revoked
      // is terminal, so a key can never be un-revoked.
      const late = await client.setKeyStatus(vm, "rotated");
      expect(late).toMatchObject({ changed: false, reason: "monotone-refused" });
      expect(state).toBe("revoked");
    });

    it("writes back the six immutable+status fields when there's no document — concurrency guard (#659)", async () => {
      // The OCC invariant at the `updateRecord` call permits exactly one
      // MUTABLE field: `status`. If a future change adds any other mutable
      // field to the update payload (e.g. a divergent `revokedAt` / `reason`),
      // it must first close the lost-update race at the DeDi side — this test
      // fails loudly to force that conversation.
      const client = createClient("example.com");
      const api = mockApi();
      mockResolveKey(api, "active");
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      await client.setKeyStatus(vm, "revoked");

      const details = vi.mocked(api.updateRecord).mock.calls[0]![3] as Record<string, unknown>;
      expect(Object.keys(details).sort()).toEqual([
        "algorithm",
        "controllerDid",
        "keyId",
        "publicKeyJwk",
        "purpose",
        "status",
      ]);
    });

    it("carries an immutable document snapshot forward unchanged (#670)", async () => {
      // When a key record carries a did.json `document` snapshot, setKeyStatus
      // carries it forward verbatim. It's immutable, so all concurrent writers
      // write the same value — no divergence, no lost-update race. `status`
      // stays the only mutated field.
      const client = createClient("example.com");
      const api = mockApi();
      const snapshot = { id: "did:web:acme.com", verificationMethod: [{ id: vm }] };
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: recordName,
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: { ...existingKey("active"), document: snapshot },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      await client.setKeyStatus(vm, "revoked");

      const details = vi.mocked(api.updateRecord).mock.calls[0]![3] as Record<string, unknown>;
      expect(Object.keys(details).sort()).toEqual([
        "algorithm",
        "controllerDid",
        "document",
        "keyId",
        "publicKeyJwk",
        "purpose",
        "status",
      ]);
      expect(details["document"]).toEqual(snapshot); // immutable — unchanged
      expect(details["status"]).toBe("revoked"); // the only mutation
    });
  });

  // ── resolveDidWebDocument (did:web fallback projection, #670) ─────────

  describe("resolveDidWebDocument", () => {
    const did = "did:web:acme.com";
    const docFor = (kid: string) => ({ id: did, verificationMethod: [{ id: kid }] });
    function keyRecord(
      kid: string,
      status: "active" | "rotated" | "revoked",
      withDoc: boolean,
    ): Record<string, unknown> {
      const base: Record<string, unknown> = {
        keyId: kid,
        controllerDid: kid.split("#")[0],
        algorithm: "ES256",
        publicKeyJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
        purpose: ["assertionMethod"],
        status,
      };
      if (withDoc) base["document"] = docFor(kid);
      return base;
    }
    function mockQuery(
      api: InstanceType<typeof DeDiApiClient>,
      details: Record<string, unknown>[],
    ) {
      vi.mocked(api.queryRecords).mockResolvedValue({
        message: "ok",
        data: details.map((d) => ({
          record_name: (d["keyId"] as string).replace(/[:#]/g, "-"),
          registry: OPENCRED_KEY_REGISTRY,
          namespace: "example.com",
          details: d,
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        })),
      } as never);
    }

    it("returns the active key's document snapshot", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      mockQuery(api, [
        keyRecord(`${did}#key-0`, "rotated", true),
        keyRecord(`${did}#key-1`, "active", true),
      ]);
      const doc = await client.resolveDidWebDocument(did);
      expect(doc).toEqual(docFor(`${did}#key-1`));
      expect(api.queryRecords).toHaveBeenCalledWith("example.com", OPENCRED_KEY_REGISTRY);
    });

    it("prefers the highest-index active key when several are active (rotation window)", async () => {
      // During the brief window between publishing the new key and flipping the
      // prior key to `rotated`, both are `active`. The stale prior key (whose
      // snapshot predates the new key) is listed first, but the projection must
      // pick the highest-index active key so the result stays current.
      const client = createClient("example.com");
      const api = mockApi();
      mockQuery(api, [
        keyRecord(`${did}#key-0`, "active", true),
        keyRecord(`${did}#key-1`, "active", true),
      ]);
      const doc = await client.resolveDidWebDocument(did);
      expect(doc).toEqual(docFor(`${did}#key-1`));
    });

    it("falls back to the highest-index key when none is active", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      mockQuery(api, [
        keyRecord(`${did}#key-0`, "revoked", true),
        keyRecord(`${did}#key-1`, "revoked", true),
      ]);
      const doc = await client.resolveDidWebDocument(did);
      expect(doc).toEqual(docFor(`${did}#key-1`));
    });

    it("ignores keys for other DIDs and keys with no document", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      mockQuery(api, [
        keyRecord("did:web:other.com#key-0", "active", true),
        keyRecord(`${did}#key-0`, "active", false),
      ]);
      const doc = await client.resolveDidWebDocument(did);
      expect(doc).toBeNull();
    });

    it("returns null when the registry query has no records", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.queryRecords).mockResolvedValue({ message: "ok", data: [] } as never);
      const doc = await client.resolveDidWebDocument(did);
      expect(doc).toBeNull();
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

      await expect(client.resolveKey("did:key:z6Mk123#z6Mk123")).rejects.toThrow(
        "DeDi API lookupRecord data response missing required field: details",
      );
    });

    it("throws when lookupRecord returns response without record_name field", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: { details: { keyId: "did:key:z6Mk123#z6Mk123" } },
      } as never);

      await expect(client.resolveKey("did:key:z6Mk123#z6Mk123")).rejects.toThrow(
        "DeDi API lookupRecord data response missing required field: record_name",
      );
    });

    it("throws when lookupRecord returns response without data field", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
      } as never);

      await expect(client.resolveKey("did:key:z6Mk123#z6Mk123")).rejects.toThrow(
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
