/**
 * Tests for two new endpoints/features:
 *
 *   1. `POST /v1/credentials/issue` with `inlineSchema` — caller pastes a
 *      JSON Schema in the body and the server validates the credential
 *      subject against it without consulting the registry.
 *   2. `POST /v1/keys/publish` and `POST /v1/keys/resolve` — DeDi
 *      public-key registry. 503 when DeDi unconfigured, 200 with a
 *      `PublishResult` / `DIDRecord` when configured.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import {
  createTestApp,
  generateTestKey,
  FUNCTIONAL_IDENTITY_SUBJECT,
  type TestKeyPair,
} from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { setDeDiClient, resetDeDiClient } from "../dedi-singleton.js";
import type { Hono } from "hono";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
  resetDeDiClient();
});

// ---------------------------------------------------------------------------
// POST /v1/credentials/issue with inlineSchema
// ---------------------------------------------------------------------------

const SUBJECT_ONLY_INLINE_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://example.org/schemas/training-cert/v1.json",
  title: "Training Certificate",
  type: "object",
  required: ["name", "course", "passedOn"],
  properties: {
    name: { type: "string", minLength: 1 },
    course: { type: "string", minLength: 1 },
    passedOn: { type: "string", format: "date" },
    score: { type: "number", minimum: 0, maximum: 100 },
  },
};

const TRAINING_SUBJECT = {
  name: "Jane Doe",
  course: "Bootcamp 101",
  passedOn: "2026-04-27",
  score: 95,
};

describe("POST /v1/credentials/issue with inlineSchema", () => {
  it("issues a credential when only inlineSchema is provided (no schemaId)", async () => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        inlineSchema: SUBJECT_ONLY_INLINE_SCHEMA,
        issuerDid: "did:key:test-issuer",
        credentialSubject: TRAINING_SUBJECT,
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(200);

    // For vc-jwt with `isCompactToken=false`, the route auto-parses the
    // signed credential before returning it, so `body.credential` is the
    // VC object directly. (For sd-jwt-vc it would be a compact string.)
    const body = (await res.json()) as {
      credential: { credentialSchema?: { id?: string; type?: string } };
      proofFormat: string;
      isCompactToken: boolean;
    };
    expect(body.proofFormat).toBe("vc-jwt");
    expect(body.isCompactToken).toBe(false);
    expect(body.credential.credentialSchema?.id).toBe(SUBJECT_ONLY_INLINE_SCHEMA.$id);
    expect(body.credential.credentialSchema?.type).toBe("JsonSchema");
  });

  it("validates credentialSubject against the inlineSchema (rejects missing required field)", async () => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        inlineSchema: SUBJECT_ONLY_INLINE_SCHEMA,
        issuerDid: "did:key:test-issuer",
        credentialSubject: {
          name: "Jane Doe",
          // missing `course` and `passedOn`
        },
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("SCHEMA_VALIDATION_ERROR");
  });

  it("falls back to a base64 data-URI when inlineSchema has no $id", async () => {
    const noIdSchema = {
      ...SUBJECT_ONLY_INLINE_SCHEMA,
      $id: undefined,
    };
    delete (noIdSchema as { $id?: unknown }).$id;

    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        inlineSchema: noIdSchema,
        issuerDid: "did:key:test-issuer",
        credentialSubject: TRAINING_SUBJECT,
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      credential: { credentialSchema?: { id?: string } };
    };
    expect(body.credential.credentialSchema?.id).toMatch(/^data:application\/schema\+json;base64,/);
  });

  it("rejects requests with neither schemaId nor inlineSchema", async () => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        issuerDid: "did:key:test-issuer",
        credentialSubject: TRAINING_SUBJECT,
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });

  it("still rejects PEM private-key strings smuggled inside an inline schema description", async () => {
    const malicious = {
      ...SUBJECT_ONLY_INLINE_SCHEMA,
      description:
        "Innocent description\n-----BEGIN PRIVATE KEY-----\nABCD\n-----END PRIVATE KEY-----",
    };
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        inlineSchema: malicious,
        issuerDid: "did:key:test-issuer",
        credentialSubject: TRAINING_SUBJECT,
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.message).toMatch(/private key/i);
  });

  it("works when both schemaId AND inlineSchema are provided (inline wins)", async () => {
    // schemaId is a registered built-in but the inline schema has different
    // required fields. The inline schema should drive validation.
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1", // built-in, but inline overrides
        inlineSchema: SUBJECT_ONLY_INLINE_SCHEMA,
        issuerDid: "did:key:test-issuer",
        credentialSubject: TRAINING_SUBJECT, // satisfies inline only
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      credential: { credentialSchema?: { id?: string } };
    };
    // Inline $id wins over registry $id when both are present.
    expect(body.credential.credentialSchema?.id).toBe(SUBJECT_ONLY_INLINE_SCHEMA.$id);
  });

  it("validates correctly even when inline subject would have failed registry validation", async () => {
    // FUNCTIONAL_IDENTITY_SUBJECT is shaped for functional-identity/v1.
    // Use it as the subject but provide an inline schema that requires
    // different fields — should fail.
    const strictInline = {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: ["completelyDifferentField"],
      properties: { completelyDifferentField: { type: "string" } },
    };
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        inlineSchema: strictInline,
        issuerDid: "did:key:test-issuer",
        credentialSubject: FUNCTIONAL_IDENTITY_SUBJECT,
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("SCHEMA_VALIDATION_ERROR");
  });

  // Regression: sd-jwt-vc verifiers route on `vct`. When the caller pastes
  // an inline schema with no $id/title, declares no additionalTypes, and
  // omits schemaId, the generic "VerifiableCredential" fallback would
  // produce a non-discriminating token. Reject early with 400 instead.
  it("rejects sd-jwt-vc when no vct can be derived (no schemaId, no inline title, no additionalTypes)", async () => {
    const titlelessSchema = {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: ["name"],
      properties: { name: { type: "string", minLength: 1 } },
    };
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        inlineSchema: titlelessSchema,
        issuerDid: "did:key:test-issuer",
        credentialSubject: { name: "Jane Doe" },
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "sd-jwt-vc",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.message).toMatch(/credential type identifier/i);
  });

  it("issues sd-jwt-vc when inlineSchema.title supplies the vct", async () => {
    const res = await app.request("/v1/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        inlineSchema: SUBJECT_ONLY_INLINE_SCHEMA, // has title: "Training Certificate"
        issuerDid: "did:key:test-issuer",
        credentialSubject: TRAINING_SUBJECT,
        validFrom: "2026-04-27T00:00:00Z",
        proofFormat: "sd-jwt-vc",
      }),
    });
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// POST /v1/keys/publish
// ---------------------------------------------------------------------------
//
// The server now publishes its OWN active signer's key — no `did`/`document`
// in the request body. The route calls `dediClient.publishKey(keyRecord)`.
//
// The active signer must have `publicKeyJwk` on its metadata (software signers
// do; PKCS#11 / KMS signers do not). The publish tests install a signer with
// `publicKeyJwk` explicitly since `generateTestKey()` does not set it.

/** Build a minimal did:key signer that has publicKeyJwk on its metadata. */
function makeSignerWithJwk(
  jwk: Record<string, unknown> = { kty: "EC", crv: "P-256", x: "x-val", y: "y-val" },
): Parameters<typeof setActiveSigner>[0] {
  return {
    id: "did:key:z6MkPublishTestKey#z6MkPublishTestKey",
    algorithm: "P-256",
    type: "software",
    metadata: {
      id: "did:key:z6MkPublishTestKey#z6MkPublishTestKey",
      algorithm: "P-256",
      type: "software",
      fingerprint: "abcd1234".repeat(8),
      publicKeyJwk: jwk,
    },
    async sign() {
      throw new Error("not needed by publish tests");
    },
  };
}

describe("POST /v1/keys/publish", () => {
  it("returns 503 when DeDi is not configured", async () => {
    setActiveSigner(makeSignerWithJwk());
    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("DEDI_NOT_CONFIGURED");
  });

  it("publishes the active signer's key to DeDi when configured", async () => {
    setActiveSigner(makeSignerWithJwk());
    const publishKeyCalls: Array<{ key: Record<string, unknown>; namespace?: string }> = [];
    const mockClient = {
      publishKey: async (key: Record<string, unknown>, namespace?: string) => {
        publishKeyCalls.push({ key, namespace });
        return {
          published: true,
          recordName: "did-key-test-key-record",
          namespace: namespace ?? "default-ns",
        };
      },
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      published: boolean;
      recordName: string;
      keyId: string;
      didDocumentStored: boolean;
    };
    expect(body.published).toBe(true);
    expect(body.recordName).toBe("did-key-test-key-record");
    expect(body.didDocumentStored).toBe(false);
    expect(typeof body.keyId).toBe("string");
    // publishKey must have been called with a KeyRecord for the active signer
    expect(publishKeyCalls).toHaveLength(1);
    expect(publishKeyCalls[0]!.key).toMatchObject({
      status: "active",
      purpose: ["assertionMethod"],
    });
  });

  it("forwards the namespace override to the DeDi client", async () => {
    setActiveSigner(makeSignerWithJwk());
    const publishKeyCalls: Array<{ namespace?: string }> = [];
    const mockClient = {
      publishKey: async (_key: unknown, namespace?: string) => {
        publishKeyCalls.push({ namespace });
        return {
          published: true,
          recordName: "did-key-test",
          namespace: namespace ?? "default-ns",
        };
      },
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ namespace: "bootcamp-2026-04-27" }),
    });
    expect(res.status).toBe(200);
    expect(publishKeyCalls[0]!.namespace).toBe("bootcamp-2026-04-27");
  });

  it("returns 400 when no signer is loaded", async () => {
    setActiveSigner(null);
    const mockClient = { publishKey: async () => ({}) } as never;
    setDeDiClient(mockClient);
    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });

  it("returns 400 VALIDATION_ERROR when the active signer has no publicKeyJwk (KMS case)", async () => {
    // KMS-backed signers don't surface publicKeyJwk — route must reject gracefully.
    const noJwkSigner: Parameters<typeof setActiveSigner>[0] = {
      id: "did:key:z6MkNoJwk#z6MkNoJwk",
      algorithm: "P-256",
      type: "pkcs11",
      metadata: {
        id: "did:key:z6MkNoJwk#z6MkNoJwk",
        algorithm: "P-256",
        type: "pkcs11",
        fingerprint: "deadbeef".repeat(8),
      },
      async sign() {
        throw new Error("unused");
      },
    };
    setActiveSigner(noJwkSigner);
    const mockClient = { publishKey: async () => ({}) } as never;
    setDeDiClient(mockClient);
    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });

  it("rejects a payload that smuggles a private key field", async () => {
    const mockClient = { publishKey: async () => ({}) } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        // The forbidden field name is rejected at any depth.
        privateKey: "should be rejected",
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.message).toMatch(/private/i);
  });
});

// ---------------------------------------------------------------------------
// POST /v1/keys/resolve
// ---------------------------------------------------------------------------
//
// Now keyed by `verificationMethod` (not `did`). Returns a KeyRecord:
//   { keyId, controllerDid, algorithm, publicKeyJwk, purpose, status, proof? }

const SAMPLE_KEY_RECORD = {
  keyId: "did:web:bootcamp.example.org#key-0",
  controllerDid: "did:web:bootcamp.example.org",
  algorithm: "P-256",
  publicKeyJwk: {
    kty: "EC",
    crv: "P-256",
    x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  },
  purpose: ["assertionMethod"],
  status: "active" as const,
};

describe("POST /v1/keys/resolve", () => {
  it("returns 503 when DeDi is not configured", async () => {
    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationMethod: "did:web:bootcamp.example.org#key-0" }),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("DEDI_NOT_CONFIGURED");
  });

  it("returns the resolved KeyRecord when DeDi is configured", async () => {
    const mockClient = {
      resolveKey: async (verificationMethod: string) => ({
        ...SAMPLE_KEY_RECORD,
        keyId: verificationMethod,
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationMethod: "did:web:bootcamp.example.org#key-0" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      keyId: string;
      controllerDid: string;
      algorithm: string;
      publicKeyJwk: Record<string, unknown>;
      purpose: string[];
      status: string;
    };
    expect(body.keyId).toBe("did:web:bootcamp.example.org#key-0");
    expect(body.controllerDid).toBe("did:web:bootcamp.example.org");
    expect(body.status).toBe("active");
    expect(body.publicKeyJwk).toMatchObject({ kty: "EC", crv: "P-256" });
  });

  it("returns a rotated KeyRecord with status: 'rotated'", async () => {
    const mockClient = {
      resolveKey: async (verificationMethod: string) => ({
        ...SAMPLE_KEY_RECORD,
        keyId: verificationMethod,
        status: "rotated" as const,
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationMethod: "did:web:bootcamp.example.org#key-0" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("rotated");
  });

  it("returns 400 when verificationMethod is missing", async () => {
    const mockClient = { resolveKey: async () => ({}) } as never;
    setDeDiClient(mockClient);
    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Auth checks (separate app with apiKey enforced)
// ---------------------------------------------------------------------------

describe("auth on the new endpoints", () => {
  it("rejects /v1/keys/publish without Bearer token", async () => {
    const authedApp = createTestApp({ apiKey: "secret-token" });
    setActiveSigner(testKey.signer);
    const res = await authedApp.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(401);
  });

  it("rejects /v1/keys/resolve without Bearer token", async () => {
    const authedApp = createTestApp({ apiKey: "secret-token" });
    setActiveSigner(testKey.signer);
    const res = await authedApp.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationMethod: "did:web:foo#key-0" }),
    });
    expect(res.status).toBe(401);
  });

  it("rejects /v1/keys/rotate without Bearer token", async () => {
    const authedApp = createTestApp({ apiKey: "secret-token" });
    setActiveSigner(testKey.signer);
    const res = await authedApp.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// POST /v1/keys/rotate — verification matrix from spike §10
// ---------------------------------------------------------------------------

/**
 * Build a synthetic did:web signer for rotation tests. The active signer's
 * `id` and `metadata.publicKeyJwk` are what the route handler reads to
 * derive the rotation target DID and the new VM payload.
 */
function buildDidWebSigner(
  host: string,
  publicKeyJwk: Record<string, unknown>,
): Parameters<typeof setActiveSigner>[0] {
  const did = `did:web:${host}`;
  return {
    id: `${did}#key-1`,
    algorithm: "P-256",
    type: "software",
    metadata: {
      id: `${did}#key-1`,
      algorithm: "P-256",
      type: "software",
      fingerprint: "deadbeef".repeat(8),
      label: "test-did-web-key",
      publicKeyJwk,
    },
    async sign() {
      throw new Error("not used by /v1/keys/rotate tests");
    },
  };
}

describe("POST /v1/keys/rotate", () => {
  const HOST = "issuer.test.local";
  const DID = `did:web:${HOST}`;
  const NEW_JWK = { kty: "EC", crv: "P-256", x: "x-new", y: "y-new" };

  /**
   * Build a minimal DeDiClient stub for rotation tests.
   * The rotate route calls: publishKey (new key), setKeyStatus (retire old key),
   * resolveKey (look up old key for did.json rebuild), publishDidDocument (optional).
   */
  function makeRotateMockClient(
    opts: {
      publishKeyResult?: Record<string, unknown>;
      setKeyStatusResult?: Record<string, unknown>;
      resolveKeyResult?: Record<string, unknown> | null;
      publishDidDocumentResult?: Record<string, unknown>;
      namespace?: string;
    } = {},
  ) {
    const publishKeyCalls: Array<{ key: Record<string, unknown>; namespace?: string }> = [];
    const setKeyStatusCalls: Array<{ vm: string; status: string; namespace?: string }> = [];
    const publishDidDocumentCalls: Array<{ did: string; namespace?: string }> = [];

    const client = {
      publishKey: async (key: Record<string, unknown>, namespace?: string) => {
        publishKeyCalls.push({ key, namespace });
        return (
          opts.publishKeyResult ?? {
            published: true,
            recordName: `${DID}#key-0`,
            namespace: namespace ?? "default-ns",
          }
        );
      },
      setKeyStatus: async (vm: string, status: string, namespace?: string) => {
        setKeyStatusCalls.push({ vm, status, namespace });
        return (
          opts.setKeyStatusResult ?? {
            changed: true,
            keyId: vm,
            from: "active",
            to: status,
            namespace: namespace ?? "default-ns",
          }
        );
      },
      resolveKey: async (_vm: string, _namespace?: string) => {
        if (opts.resolveKeyResult === null) throw new Error("not found");
        return (
          opts.resolveKeyResult ?? {
            keyId: _vm,
            controllerDid: DID,
            algorithm: "P-256",
            publicKeyJwk: { kty: "EC", crv: "P-256", x: "x-old", y: "y-old" },
            purpose: ["assertionMethod"],
            status: "rotated",
          }
        );
      },
      publishDidDocument: async (did: string, _doc: unknown, namespace?: string) => {
        publishDidDocumentCalls.push({ did, namespace });
        return (
          opts.publishDidDocumentResult ?? {
            published: true,
            recordName: did,
            namespace: namespace ?? "default-ns",
          }
        );
      },
    } as never;

    return { client, publishKeyCalls, setKeyStatusCalls, publishDidDocumentCalls };
  }

  it("returns 503 when DeDi is not configured", async () => {
    setActiveSigner(buildDidWebSigner(HOST, NEW_JWK));
    const res = await app.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("DEDI_NOT_CONFIGURED");
  });

  it("returns 400 KEY_METHOD_MISMATCH when the active signer is did:key", async () => {
    // testKey is a did:key signer (built by generateTestKey).
    setActiveSigner(testKey.signer);
    // Even with DeDi configured, the route rejects did:key before reaching DeDi.
    const { client } = makeRotateMockClient();
    setDeDiClient(client);
    const res = await app.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; activeDid: string } };
    expect(body.error.code).toBe("KEY_METHOD_MISMATCH");
    expect(body.error.activeDid).toMatch(/^did:key:/);
  });

  it("returns 400 VALIDATION_ERROR when the signer has no publicKeyJwk", async () => {
    // Construct a did:web signer whose metadata lacks publicKeyJwk —
    // this is the KMS-backed-signer case the route guards against.
    const noJwkSigner: Parameters<typeof setActiveSigner>[0] = {
      id: `${DID}#key-1`,
      algorithm: "P-256",
      type: "pkcs11",
      metadata: {
        id: `${DID}#key-1`,
        algorithm: "P-256",
        type: "pkcs11",
        fingerprint: "deadbeef".repeat(8),
      },
      async sign() {
        throw new Error("unused");
      },
    };
    setActiveSigner(noJwkSigner);
    const { client } = makeRotateMockClient();
    setDeDiClient(client);
    const res = await app.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; signerType: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.signerType).toBe("pkcs11");
  });

  it("publishes the new key and returns rotated:true with currentKeyId", async () => {
    setActiveSigner(buildDidWebSigner(HOST, NEW_JWK));
    const { client, publishKeyCalls } = makeRotateMockClient();
    setDeDiClient(client);

    const res = await app.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      rotated: boolean;
      did: string;
      currentKeyId: string;
      retired: null | Record<string, unknown>;
      didDocumentStored: boolean;
    };
    expect(body.rotated).toBe(true);
    expect(body.did).toBe(DID);
    // The new key's keyId is `<did>#key-0` (did:web pattern)
    expect(body.currentKeyId).toBe(`${DID}#key-0`);
    expect(body.retired).toBeNull();
    expect(body.didDocumentStored).toBe(false);

    // publishKey must have been called for the new key
    expect(publishKeyCalls).toHaveLength(1);
    expect(publishKeyCalls[0]!.key).toMatchObject({
      controllerDid: DID,
      status: "active",
      publicKeyJwk: NEW_JWK,
    });
  });

  it("retires the previous VM when previousVerificationMethod is provided", async () => {
    setActiveSigner(buildDidWebSigner(HOST, NEW_JWK));
    const PREV_VM = `${DID}#key-1`;
    const { client, setKeyStatusCalls } = makeRotateMockClient();
    setDeDiClient(client);

    const res = await app.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ previousVerificationMethod: PREV_VM }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      rotated: boolean;
      retired: Record<string, unknown> | null;
    };
    expect(body.rotated).toBe(true);
    // setKeyStatus called for the previous key
    expect(setKeyStatusCalls).toHaveLength(1);
    expect(setKeyStatusCalls[0]!.vm).toBe(PREV_VM);
    expect(setKeyStatusCalls[0]!.status).toBe("rotated");
    // The SetKeyStatusResult is forwarded as `retired`
    expect(body.retired).not.toBeNull();
    expect(body.retired!.changed).toBe(true);
  });

  it("stores the did.json when hostDidDocument=true", async () => {
    setActiveSigner(buildDidWebSigner(HOST, NEW_JWK));
    const { client, publishDidDocumentCalls } = makeRotateMockClient();
    setDeDiClient(client);

    const res = await app.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hostDidDocument: true }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { didDocumentStored: boolean };
    expect(body.didDocumentStored).toBe(true);
    expect(publishDidDocumentCalls).toHaveLength(1);
    expect(publishDidDocumentCalls[0]!.did).toBe(DID);
  });

  it("forwards the namespace override to the adapter", async () => {
    setActiveSigner(buildDidWebSigner(HOST, NEW_JWK));
    const { client, publishKeyCalls } = makeRotateMockClient();
    setDeDiClient(client);

    const res = await app.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ namespace: "explicit-ns" }),
    });
    expect(res.status).toBe(200);
    expect(publishKeyCalls[0]!.namespace).toBe("explicit-ns");
  });

  it("returns 400 when no signer is loaded", async () => {
    setActiveSigner(null);
    const { client } = makeRotateMockClient();
    setDeDiClient(client);
    const res = await app.request("/v1/keys/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });
});

// ---------------------------------------------------------------------------
// GET /v1/keys/did-document — operator-side did.json export
// ---------------------------------------------------------------------------
//
// Path A operators (self-host .well-known/did.json) need the canonical
// document JSON for upload to their domain. Path B operators want to fetch
// what they (or auto-publish) wrote to DeDi so they can mirror it locally.
// The endpoint serves both: prefers DeDi's record when configured (carries
// rotation history), falls back to deriving from the active signer's JWK.

describe("GET /v1/keys/did-document", () => {
  const HOST = "issuer.test.local";
  const DID = `did:web:${HOST}`;
  const JWK = { kty: "EC", crv: "P-256", x: "x-bytes", y: "y-bytes" } as Record<string, unknown>;

  it("returns 503 when no signer is loaded", async () => {
    setActiveSigner(null);
    const res = await app.request("/v1/keys/did-document");
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("NO_SIGNER");
  });

  it("returns 400 UNSUPPORTED_DID_METHOD for did:key issuers", async () => {
    // testKey is a did:key signer; the endpoint should reject because
    // did:key DIDs are self-resolving and don't need a .well-known/did.json.
    setActiveSigner(testKey.signer);
    const res = await app.request("/v1/keys/did-document");
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; activeDid: string } };
    expect(body.error.code).toBe("UNSUPPORTED_DID_METHOD");
    expect(body.error.activeDid).toMatch(/^did:key:/);
  });

  it("derives the document from active signer when DeDi is not configured", async () => {
    setActiveSigner(buildDidWebSigner(HOST, JWK));
    // No setDeDiClient — beforeEach resets it, this case validates the
    // "no DeDi" branch.
    const res = await app.request("/v1/keys/did-document");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      did: string;
      document: {
        verificationMethod: Array<{ id: string; publicKeyJwk: Record<string, unknown> }>;
      };
      source: string;
    };
    expect(body.source).toBe("active-signer");
    expect(body.did).toBe(DID);
    expect(body.document.verificationMethod[0]!.id).toBe(`${DID}#key-0`);
    expect(body.document.verificationMethod[0]!.publicKeyJwk).toEqual(JWK);
  });

  it("returns the DeDi-persisted document (with rotation history) when DeDi has the record", async () => {
    // Simulate a multi-key DeDi record — what /v1/keys/rotate produces.
    // The endpoint should surface this verbatim instead of deriving a
    // fresh single-key doc.
    const rotatedDocument = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: DID,
      verificationMethod: [
        {
          id: `${DID}#key-0`,
          type: "JsonWebKey",
          controller: DID,
          publicKeyJwk: { kty: "EC", crv: "P-256", x: "old-x", y: "old-y" },
          supersededAt: "2026-05-01T00:00:00Z",
        },
        {
          id: `${DID}#key-1`,
          type: "JsonWebKey",
          controller: DID,
          publicKeyJwk: JWK,
        },
      ],
      assertionMethod: [`${DID}#key-1`],
    };
    setActiveSigner(buildDidWebSigner(HOST, JWK));
    // Source now calls resolveDidDocument (not resolveDID)
    setDeDiClient({
      resolveDidDocument: async (did: string) => ({
        did,
        document: rotatedDocument,
      }),
    } as never);

    const res = await app.request("/v1/keys/did-document");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      did: string;
      document: { verificationMethod: Array<{ id: string; supersededAt?: string }> };
      source: string;
    };
    expect(body.source).toBe("dedi");
    // The `keyStatus` field was removed from this endpoint's response.
    // Rotation history lives inside verificationMethod[].
    expect(body.document.verificationMethod).toHaveLength(2);
    expect(body.document.verificationMethod[0]!.supersededAt).toBe("2026-05-01T00:00:00Z");
    expect(body.document.verificationMethod[1]!.id).toBe(`${DID}#key-1`);
  });

  it("falls back to active-signer derivation when DeDi returns 404 (not yet published)", async () => {
    // DeDi configured but the DID hasn't been auto-published yet (e.g. on
    // first boot before OPENCRED_AUTO_PUBLISH_KEY took effect, or when the
    // operator deliberately uses Path A only).
    setActiveSigner(buildDidWebSigner(HOST, JWK));
    setDeDiClient({
      resolveDidDocument: async () => {
        const { DeDiClientError } = await import("@opencred/shared");
        throw new DeDiClientError("Not found", 404);
      },
    } as never);

    const res = await app.request("/v1/keys/did-document");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      source: string;
      document: { verificationMethod: Array<{ id: string }> };
    };
    expect(body.source).toBe("active-signer");
    expect(body.document.verificationMethod[0]!.id).toBe(`${DID}#key-0`);
  });

  it("falls back to active-signer derivation when DeDi errors with non-404 (logs warn, continues)", async () => {
    // Auth, network, or 5xx errors shouldn't block the operator from
    // getting *some* document back — fallback is the active signer's key.
    setActiveSigner(buildDidWebSigner(HOST, JWK));
    setDeDiClient({
      resolveDidDocument: async () => {
        const { DeDiClientError } = await import("@opencred/shared");
        throw new DeDiClientError("DeDi API error: 503", 502);
      },
    } as never);

    const res = await app.request("/v1/keys/did-document");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { source: string };
    expect(body.source).toBe("active-signer");
  });

  it("returns 400 VALIDATION_ERROR when the active signer has no publicKeyJwk (KMS case) and DeDi has no record", async () => {
    // KMS-backed signers don't surface publicKeyJwk today (#635), so when
    // there's no DeDi fallback either, the endpoint cannot produce a
    // document. Surface a clear error instead of guessing.
    const kmsSigner: Parameters<typeof setActiveSigner>[0] = {
      id: `${DID}#key-1`,
      algorithm: "P-256",
      type: "pkcs11",
      metadata: {
        id: `${DID}#key-1`,
        algorithm: "P-256",
        type: "pkcs11",
        fingerprint: "deadbeef".repeat(8),
      },
      async sign() {
        throw new Error("unused");
      },
    };
    setActiveSigner(kmsSigner);
    // No DeDi configured.
    const res = await app.request("/v1/keys/did-document");
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string; signerType: string } };
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.signerType).toBe("pkcs11");
  });

  it("rejects /v1/keys/did-document without Bearer token", async () => {
    const authedApp = createTestApp({ apiKey: "secret-token" });
    setActiveSigner(buildDidWebSigner(HOST, JWK));
    const res = await authedApp.request("/v1/keys/did-document");
    expect(res.status).toBe(401);
  });
});
