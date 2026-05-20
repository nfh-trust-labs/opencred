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
      vi.mocked(api.search).mockResolvedValue({ message: "ok", data: [] });

      await client.queryRevocationHash("abc");

      expect(api.search).toHaveBeenCalledWith("example.com", expect.any(Object));
    });

    it("uses explicit namespace over defaultNamespace", async () => {
      const client = createClient("default.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({ message: "ok", data: [] });

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
  });

  // ── queryRevocationHash ──────────────────────────────────────────

  describe("queryRevocationHash", () => {
    it("searches for hash by details.revoked_id and reports revoked when present", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({
        message: "ok",
        data: [
          {
            record_name: "abc",
            registry: REVOCATION_REGISTRY,
            namespace: "example.com",
            details: { revoked_id: "abc" },
            state: "live",
            version: "1",
            created_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-02T00:00:00Z",
          },
        ],
      });

      const result = await client.queryRevocationHash("abc");

      // Search query targets the canonical revoke schema's revoked_id field.
      expect(api.search).toHaveBeenCalledWith("example.com", {
        registry_name: REVOCATION_REGISTRY,
        "details.revoked_id": "abc",
      });
      // revokedAt sourced from the envelope's updated_at; no reason on this record.
      expect(result).toEqual({ revoked: true, revokedAt: "2026-01-02T00:00:00Z" });
    });

    it("surfaces optional reason from the record details", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({
        message: "ok",
        data: [
          {
            record_name: "abc",
            registry: REVOCATION_REGISTRY,
            namespace: "example.com",
            details: { revoked_id: "abc", reason: "Key compromised" },
            state: "live",
            version: "1",
            created_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-02T00:00:00Z",
          },
        ],
      });

      const result = await client.queryRevocationHash("abc");

      expect(result).toEqual({
        revoked: true,
        revokedAt: "2026-01-02T00:00:00Z",
        reason: "Key compromised",
      });
    });

    it("returns { revoked: false } when hash not found", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({ message: "ok", data: [] });

      const result = await client.queryRevocationHash("missing");

      expect(result).toEqual({ revoked: false });
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
        tag: "revoke",
        state: "active",
        record_count: 0,
        created_at: "",
        updated_at: "",
      });

      await client.ensureRegistries("example.com");

      expect(api.lookupNamespace).toHaveBeenCalledWith("example.com");
      expect(api.createNamespace).toHaveBeenCalledWith("example.com", expect.any(String));
      expect(api.createRegistry).toHaveBeenCalledTimes(4);
      // Revocation registry now uses DeDi's canonical "revoke" tag — no
      // custom schema body, the tag drives server-side validation.
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        REVOCATION_REGISTRY,
        {},
        "revoke",
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
      expect(api.createRegistry).toHaveBeenCalledWith(
        "example.com",
        CONTEXT_REGISTRY,
        expect.any(Object),
        "custom",
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
        tag: "revoke",
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
        tag: "revoke",
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

    it("preserves the document on rotated did:web records", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      const document = { id: "did:web:acme.com", verificationMethod: [] };
      vi.mocked(api.lookupRecord).mockResolvedValue({
        message: "ok",
        data: {
          record_name: "did-web-acme.com",
          registry: PUBLIC_KEY_REGISTRY,
          namespace: "example.com",
          details: { did: "did:web:acme.com", document, keyStatus: "current" },
          state: "live",
          version: "1",
          created_at: "",
          updated_at: "",
        },
      });
      vi.mocked(api.updateRecord).mockResolvedValue({} as never);

      await client.markDIDRotated("did:web:acme.com");

      expect(api.updateRecord).toHaveBeenCalledWith(
        "example.com",
        PUBLIC_KEY_REGISTRY,
        "did-web-acme.com",
        // document preserved alongside the flipped keyStatus
        { did: "did:web:acme.com", document, keyStatus: "rotated" },
      );
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

  // ── Search result wrapper validation ────────────────────────────

  describe("search result wrapper validation", () => {
    it("throws when search returns response without data array", async () => {
      const client = createClient("example.com");
      const api = mockApi();
      vi.mocked(api.search).mockResolvedValue({ message: "ok" } as never);

      await expect(client.queryRevocationHash("abc")).rejects.toThrow(
        "DeDi API search response field 'data' must be an array",
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
