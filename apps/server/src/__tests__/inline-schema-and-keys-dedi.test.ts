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

const SAMPLE_DID_DOCUMENT = {
  "@context": "https://www.w3.org/ns/did/v1",
  id: "did:web:bootcamp.example.org",
  verificationMethod: [
    {
      id: "did:web:bootcamp.example.org#key-1",
      type: "JsonWebKey2020",
      controller: "did:web:bootcamp.example.org",
      publicKeyJwk: {
        kty: "EC",
        crv: "P-256",
        x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      },
    },
  ],
  assertionMethod: ["did:web:bootcamp.example.org#key-1"],
};

describe("POST /v1/keys/publish", () => {
  it("returns 503 when DeDi is not configured", async () => {
    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: "did:web:bootcamp.example.org",
        document: SAMPLE_DID_DOCUMENT,
      }),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("DEDI_NOT_CONFIGURED");
  });

  it("publishes a DID document to DeDi when configured", async () => {
    const calls: Array<{ did: string; document: unknown; namespace?: string }> = [];
    const mockClient = {
      publishDID: async (did: string, document: unknown, namespace?: string) => {
        calls.push({ did, document, namespace });
        return {
          published: true,
          recordName: "did-web-bootcamp-example-org",
          namespace: namespace ?? "default-ns",
        };
      },
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: "did:web:bootcamp.example.org",
        document: SAMPLE_DID_DOCUMENT,
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      published: boolean;
      recordName: string;
      namespace: string;
    };
    expect(body.published).toBe(true);
    expect(body.recordName).toBe("did-web-bootcamp-example-org");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.did).toBe("did:web:bootcamp.example.org");
  });

  it("forwards the namespace override to the DeDi client", async () => {
    const calls: Array<{ namespace?: string }> = [];
    const mockClient = {
      publishDID: async (_did: string, _doc: unknown, namespace?: string) => {
        calls.push({ namespace });
        return {
          published: true,
          recordName: "did-web-bootcamp-example-org",
          namespace: namespace ?? "default-ns",
        };
      },
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: "did:web:bootcamp.example.org",
        document: SAMPLE_DID_DOCUMENT,
        namespace: "bootcamp-2026-04-27",
      }),
    });
    expect(res.status).toBe(200);
    expect(calls[0]!.namespace).toBe("bootcamp-2026-04-27");
  });

  it("returns 400 when did is missing", async () => {
    const mockClient = { publishDID: async () => ({}) } as never;
    setDeDiClient(mockClient);
    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ document: SAMPLE_DID_DOCUMENT }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects a payload that smuggles a private key in the document", async () => {
    const mockClient = { publishDID: async () => ({}) } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: "did:web:bootcamp.example.org",
        document: {
          ...SAMPLE_DID_DOCUMENT,
          // The forbidden field name is rejected at any depth.
          privateKey: "should be rejected",
        },
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

describe("POST /v1/keys/resolve", () => {
  it("returns 503 when DeDi is not configured", async () => {
    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:web:bootcamp.example.org" }),
    });
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("DEDI_NOT_CONFIGURED");
  });

  it("returns the resolved DID record when DeDi is configured", async () => {
    const mockClient = {
      resolveDID: async (did: string) => ({
        did,
        document: SAMPLE_DID_DOCUMENT,
        keyStatus: "current" as const,
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:web:bootcamp.example.org" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      did: string;
      document: unknown;
      keyStatus: "current" | "rotated";
    };
    expect(body.did).toBe("did:web:bootcamp.example.org");
    expect(body.keyStatus).toBe("current");
    expect(body.document).toEqual(SAMPLE_DID_DOCUMENT);
  });

  it("returns a rotated DID record with keyStatus: 'rotated'", async () => {
    // Verifier consumers branch on this to surface a "rotated" badge.
    const mockClient = {
      resolveDID: async (did: string) => ({
        did,
        document: SAMPLE_DID_DOCUMENT,
        keyStatus: "rotated" as const,
      }),
    } as never;
    setDeDiClient(mockClient);

    const res = await app.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:web:bootcamp.example.org" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keyStatus: "current" | "rotated" };
    expect(body.keyStatus).toBe("rotated");
  });

  it("returns 400 when did is missing", async () => {
    const mockClient = { resolveDID: async () => ({}) } as never;
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
      body: JSON.stringify({ did: "did:web:foo", document: {} }),
    });
    expect(res.status).toBe(401);
  });

  it("rejects /v1/keys/resolve without Bearer token", async () => {
    const authedApp = createTestApp({ apiKey: "secret-token" });
    setActiveSigner(testKey.signer);
    const res = await authedApp.request("/v1/keys/resolve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did: "did:web:foo" }),
    });
    expect(res.status).toBe(401);
  });
});
