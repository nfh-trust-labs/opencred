/**
 * Tests for the startup auto-publish helper (`runAutoPublishIfEnabled`).
 *
 * Covers the full matrix surfaced in the §8 plan of
 * `docs/bootcamp/post-bootcamp-followups.md`:
 *
 *   1. Flag false  → outcome: "disabled"; no publish call
 *   2. Flag true + no signer loaded → outcome: "no-signer"
 *   3. Flag true + DeDi succeeds → outcome: "published"
 *   4. Flag true + DID already published → outcome: "already-published"
 *      (idempotent — DeDiRecordExistsError treated as success)
 *   5. Flag true + DeDi unreachable / other error → outcome: "publish-failed"
 *   6. OPENCRED_DEDI_HOST_DID_DOC=true + did:web → publish runs
 *      (regression guard for the no-op bug surfaced by the bootcamp)
 *   7. OPENCRED_DEDI_HOST_DID_DOC=true + did:key → does NOT trigger
 *      (HOST_DID_DOC is did:web-specific by design)
 *   8. did:web + signer without publicKeyJwk → outcome: "no-jwk"
 *   9. did:web success path calls publishKey with a KeyRecord + publishDidDocument
 *      when OPENCRED_DEDI_HOST_DID_DOC=true
 *  10. did:key success path calls publishKey and no publishDidDocument
 */

import { describe, it, expect, vi } from "vitest";
import { DeDiRecordExistsError } from "@opencred/shared";
import { runAutoPublishIfEnabled, type AutoPublishConfig } from "../auto-publish.js";
import type { DeDiClient, KeyRecord } from "@opencred/dedi-client";
import type { Signer, SignerMetadata } from "@opencred/signing";
import type { Logger } from "pino";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeLogger(): Pick<Logger, "info" | "warn"> & {
  info: ReturnType<typeof vi.fn>;
  warn: ReturnType<typeof vi.fn>;
} {
  return { info: vi.fn(), warn: vi.fn() };
}

function makeSoftwareSigner(
  opts: { didKey?: string; publicKeyJwk?: Record<string, unknown> } = {},
): Signer {
  const didKey = opts.didKey ?? "did:key:z6MkTestKey123";
  const id = `${didKey}#z6MkTestKey123`;
  const metadata: SignerMetadata = {
    id,
    algorithm: "P-256",
    type: "software",
    fingerprint: "deadbeef".repeat(8),
    publicKeyJwk: opts.publicKeyJwk ?? {
      kty: "EC",
      crv: "P-256",
      x: "AAA",
      y: "BBB",
    },
  };
  return {
    id,
    algorithm: "P-256",
    type: "software",
    metadata,
    sign: async () => new Uint8Array(64),
  };
}

function makePkcs11Signer(): Signer {
  // PKCS#11 signers don't expose publicKeyJwk today — regression test fixture
  // for the "no-jwk" branch when the operator picks did:web with a hardware
  // token.
  const metadata: SignerMetadata = {
    id: "did:key:z6MkPkcs11SignerXYZ#z6MkPkcs11SignerXYZ",
    algorithm: "P-256",
    type: "pkcs11",
    fingerprint: "feedface".repeat(8),
  };
  return {
    id: metadata.id,
    algorithm: "P-256",
    type: "pkcs11",
    metadata,
    sign: async () => new Uint8Array(64),
  };
}

type PublishKeyCall = { key: KeyRecord; namespace?: string };
type PublishDidDocumentCall = { did: string; document: unknown; namespace?: string };

function makeDeDiClient(opts: {
  publishKey?: (
    key: KeyRecord,
    namespace?: string,
  ) => Promise<{ recordName: string; published: boolean; namespace: string }>;
  publishDidDocument?: (did: string, document: unknown, namespace?: string) => Promise<unknown>;
}): {
  client: DeDiClient;
  publishKeyCalls: PublishKeyCall[];
  publishDidDocumentCalls: PublishDidDocumentCall[];
} {
  const publishKeyCalls: PublishKeyCall[] = [];
  const publishDidDocumentCalls: PublishDidDocumentCall[] = [];
  const client = {
    publishKey: async (key: KeyRecord, namespace?: string) => {
      publishKeyCalls.push({ key, namespace });
      if (opts.publishKey) {
        return opts.publishKey(key, namespace);
      }
      return { published: true, recordName: key.controllerDid, namespace: namespace ?? "test-ns" };
    },
    publishDidDocument: async (did: string, document: unknown, namespace?: string) => {
      publishDidDocumentCalls.push({ did, document, namespace });
      if (opts.publishDidDocument) {
        return opts.publishDidDocument(did, document, namespace);
      }
      return { published: true, recordName: did, namespace: namespace ?? "test-ns" };
    },
  } as unknown as DeDiClient;
  return { client, publishKeyCalls, publishDidDocumentCalls };
}

function makeConfig(overrides: Partial<AutoPublishConfig> = {}): AutoPublishConfig {
  return {
    OPENCRED_AUTO_PUBLISH_KEY: false,
    OPENCRED_DEDI_HOST_DID_DOC: false,
    OPENCRED_ISSUER_DID_METHOD: "key",
    OPENCRED_DEDI_NAMESPACE: "test-ns",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("runAutoPublishIfEnabled — flag matrix", () => {
  it("does nothing when both flags are off", async () => {
    const { client, publishKeyCalls } = makeDeDiClient({});
    const result = await runAutoPublishIfEnabled(
      makeConfig(),
      client,
      makeSoftwareSigner(),
      makeLogger(),
    );
    expect(result).toEqual({ didPublish: false, outcome: "disabled" });
    expect(publishKeyCalls).toHaveLength(0);
  });

  it("does nothing when OPENCRED_DEDI_HOST_DID_DOC=true but method is did:key", async () => {
    // HOST_DID_DOC is did:web-specific by design — for did:key issuers the
    // operator must use OPENCRED_AUTO_PUBLISH_KEY=true instead. Regression
    // guard against accidentally widening HOST_DID_DOC semantics.
    const { client, publishKeyCalls } = makeDeDiClient({});
    const result = await runAutoPublishIfEnabled(
      makeConfig({ OPENCRED_DEDI_HOST_DID_DOC: true, OPENCRED_ISSUER_DID_METHOD: "key" }),
      client,
      makeSoftwareSigner(),
      makeLogger(),
    );
    expect(result).toEqual({ didPublish: false, outcome: "disabled" });
    expect(publishKeyCalls).toHaveLength(0);
  });

  it("returns no-signer outcome when flag is on but no signer is loaded", async () => {
    const logger = makeLogger();
    const { client, publishKeyCalls } = makeDeDiClient({
      publishKey: async () => {
        throw new Error("should not be called");
      },
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({ OPENCRED_AUTO_PUBLISH_KEY: true }),
      client,
      null,
      logger,
    );
    expect(result).toEqual({ didPublish: false, outcome: "no-signer" });
    expect(publishKeyCalls).toHaveLength(0);
    expect(logger.warn).toHaveBeenCalledOnce();
    expect((logger.warn.mock.calls[0]![0] as string).toString()).toMatch(/no signer/i);
  });
});

describe("runAutoPublishIfEnabled — did:key success path", () => {
  it("publishes the signer's did:key as a KeyRecord and returns published outcome", async () => {
    const logger = makeLogger();
    const { client, publishKeyCalls, publishDidDocumentCalls } = makeDeDiClient({
      publishKey: async (key) => ({
        published: true,
        recordName: key.controllerDid,
        namespace: "test-ns",
      }),
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({ OPENCRED_AUTO_PUBLISH_KEY: true }),
      client,
      makeSoftwareSigner(),
      logger,
    );
    expect(result.didPublish).toBe(true);
    expect(result.outcome).toBe("published");
    if (result.outcome === "published") {
      expect(result.issuerDid).toBe("did:key:z6MkTestKey123");
      expect(result.recordName).toBe("did:key:z6MkTestKey123");
    }
    // publishKey called once; publishDidDocument NOT called for did:key
    expect(publishKeyCalls).toHaveLength(1);
    expect(publishDidDocumentCalls).toHaveLength(0);
    // The KeyRecord must carry the issuer DID as controllerDid (no fragment).
    expect(publishKeyCalls[0]!.key.controllerDid).toBe("did:key:z6MkTestKey123");
    expect(publishKeyCalls[0]!.key.status).toBe("active");
    expect(publishKeyCalls[0]!.key.publicKeyJwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(publishKeyCalls[0]!.namespace).toBe("test-ns");
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ issuerDid: "did:key:z6MkTestKey123" }),
      expect.stringContaining("auto-published"),
    );
  });

  it("strips the #fragment from signer.id to derive the bare DID", async () => {
    // signer.id is `did:key:<multibase>#<multibase>` (verification-method id).
    // The KeyRecord.controllerDid must use the BARE did, not the full vm-id.
    const { client, publishKeyCalls } = makeDeDiClient({
      publishKey: async (key) => ({
        published: true,
        recordName: key.controllerDid,
        namespace: "test-ns",
      }),
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({ OPENCRED_AUTO_PUBLISH_KEY: true }),
      client,
      makeSoftwareSigner({ didKey: "did:key:z6MkAnotherKey" }),
      makeLogger(),
    );
    expect(result.outcome).toBe("published");
    expect(publishKeyCalls[0]!.key.controllerDid).toBe("did:key:z6MkAnotherKey");
    expect(publishKeyCalls[0]!.key.controllerDid).not.toContain("#");
  });
});

describe("runAutoPublishIfEnabled — did:web success path", () => {
  it("publishes did:web as a KeyRecord (no publishDidDocument when HOST_DID_DOC=false)", async () => {
    const { client, publishKeyCalls, publishDidDocumentCalls } = makeDeDiClient({
      publishKey: async (_key) => ({
        published: true,
        recordName: "did-web-bootcamp-example-org",
        namespace: "test-ns",
      }),
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({
        OPENCRED_AUTO_PUBLISH_KEY: true,
        OPENCRED_ISSUER_DID_METHOD: "web",
        OPENCRED_ISSUER_DOMAIN: "bootcamp.example.org",
      }),
      client,
      makeSoftwareSigner(),
      makeLogger(),
    );
    expect(result.outcome).toBe("published");
    if (result.outcome === "published") {
      expect(result.issuerDid).toBe("did:web:bootcamp.example.org");
    }
    // publishKey called once
    expect(publishKeyCalls).toHaveLength(1);
    expect(publishKeyCalls[0]!.key.controllerDid).toBe("did:web:bootcamp.example.org");
    // keyId for did:web must be `<did>#key-0`
    expect(publishKeyCalls[0]!.key.keyId).toBe("did:web:bootcamp.example.org#key-0");
    // The KeyRecord must carry the signer's publicKeyJwk so verifiers can match by kid.
    expect(publishKeyCalls[0]!.key.publicKeyJwk).toMatchObject({
      kty: "EC",
      crv: "P-256",
    });
    // No publishDidDocument when HOST_DID_DOC=false
    expect(publishDidDocumentCalls).toHaveLength(0);
  });

  it("calls publishDidDocument ALSO when OPENCRED_DEDI_HOST_DID_DOC=true + did:web", async () => {
    // Regression guard: HOST_DID_DOC=true + method=web must both call
    // publishKey AND publishDidDocument with a generated did.json.
    const { client, publishKeyCalls, publishDidDocumentCalls } = makeDeDiClient({
      publishKey: async (_key) => ({
        published: true,
        recordName: "did-web-issuer-example-org",
        namespace: "test-ns",
      }),
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({
        OPENCRED_AUTO_PUBLISH_KEY: false,
        OPENCRED_DEDI_HOST_DID_DOC: true,
        OPENCRED_ISSUER_DID_METHOD: "web",
        OPENCRED_ISSUER_DOMAIN: "issuer.example.org",
      }),
      client,
      makeSoftwareSigner(),
      makeLogger(),
    );
    expect(result.outcome).toBe("published");
    expect(publishKeyCalls).toHaveLength(1);
    expect(publishKeyCalls[0]!.key.controllerDid).toBe("did:web:issuer.example.org");
    // publishDidDocument must have been called with the generated did.json
    expect(publishDidDocumentCalls).toHaveLength(1);
    expect(publishDidDocumentCalls[0]!.did).toBe("did:web:issuer.example.org");
    const doc = publishDidDocumentCalls[0]!.document as {
      id: string;
      verificationMethod: Array<{ publicKeyJwk: Record<string, unknown> }>;
    };
    expect(doc).toBeDefined();
    expect(doc.id).toBe("did:web:issuer.example.org");
    expect(doc.verificationMethod).toBeDefined();
    expect(doc.verificationMethod[0]!.publicKeyJwk).toMatchObject({
      kty: "EC",
      crv: "P-256",
    });
  });

  it("returns no-jwk outcome when did:web signer lacks publicKeyJwk", async () => {
    // PKCS#11 / OS-cert signers don't expose publicKeyJwk today. The
    // helper must skip the publish gracefully rather than throwing or
    // generating a malformed document.
    const logger = makeLogger();
    const { client, publishKeyCalls } = makeDeDiClient({
      publishKey: async () => {
        throw new Error("should not be called");
      },
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({
        OPENCRED_AUTO_PUBLISH_KEY: true,
        OPENCRED_ISSUER_DID_METHOD: "web",
        OPENCRED_ISSUER_DOMAIN: "issuer.example.org",
      }),
      client,
      makePkcs11Signer(),
      logger,
    );
    expect(result.didPublish).toBe(false);
    expect(result.outcome).toBe("no-jwk");
    if (result.outcome === "no-jwk") {
      expect(result.signerType).toBe("pkcs11");
      expect(result.issuerDid).toBe("did:web:issuer.example.org");
    }
    expect(publishKeyCalls).toHaveLength(0);
    expect(logger.warn).toHaveBeenCalledOnce();
    expect((logger.warn.mock.calls[0]![1] as string).toString()).toMatch(/publicKeyJwk/);
  });
});

describe("runAutoPublishIfEnabled — failure modes", () => {
  it("treats DeDiRecordExistsError as success (idempotent skip)", async () => {
    // The key was published in a prior run. From the auto-publish flag's
    // perspective the precondition holds — verifiers can resolve via DeDi
    // right now — so we surface this as didPublish: true with a distinct
    // outcome string so logs and tests can tell apart "fresh publish" from
    // "already there."
    const logger = makeLogger();
    const { client } = makeDeDiClient({
      publishKey: async () => {
        throw new DeDiRecordExistsError(
          "This key is already in the public key registry",
          "Use POST /v1/keys/resolve to fetch the existing record",
          { message: "duplicate record name" },
        );
      },
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({ OPENCRED_AUTO_PUBLISH_KEY: true }),
      client,
      makeSoftwareSigner(),
      logger,
    );
    expect(result.didPublish).toBe(true);
    expect(result.outcome).toBe("already-published");
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ issuerDid: expect.any(String) }),
      expect.stringContaining("already published"),
    );
    // Critically: NO warn log on this branch — operators reading logs
    // should not see this as an error.
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("treats other DeDi errors as non-fatal warning, returns publish-failed", async () => {
    // Network error, auth failure, anything that's not a duplicate-record
    // signal. The server must still start; the helper records the failure
    // for /v1/health to surface.
    const logger = makeLogger();
    const { client } = makeDeDiClient({
      publishKey: async () => {
        throw new Error("ECONNREFUSED 127.0.0.1:9000");
      },
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({ OPENCRED_AUTO_PUBLISH_KEY: true }),
      client,
      makeSoftwareSigner(),
      logger,
    );
    expect(result.didPublish).toBe(false);
    expect(result.outcome).toBe("publish-failed");
    if (result.outcome === "publish-failed") {
      expect(result.error).toMatch(/ECONNREFUSED/);
    }
    expect(logger.warn).toHaveBeenCalledOnce();
    expect((logger.warn.mock.calls[0]![1] as string).toString()).toMatch(/non-fatal/);
  });

  it("never throws even when the dediClient rejection is non-Error", async () => {
    // Defensive: some libraries throw bare strings or objects. The helper
    // must coerce to a string and not propagate.
    const { client } = makeDeDiClient({
      publishKey: async () => {
        throw "string error from a misbehaving client";
      },
    });
    const result = await runAutoPublishIfEnabled(
      makeConfig({ OPENCRED_AUTO_PUBLISH_KEY: true }),
      client,
      makeSoftwareSigner(),
      makeLogger(),
    );
    expect(result.didPublish).toBe(false);
    expect(result.outcome).toBe("publish-failed");
    if (result.outcome === "publish-failed") {
      expect(result.error).toBe("string error from a misbehaving client");
    }
  });
});
