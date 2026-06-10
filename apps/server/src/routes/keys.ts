/**
 * Keys endpoints — three responsibilities:
 *
 *   1. `GET  /keys`           — metadata about the loaded signing key
 *   2. `POST /keys/publish`   — publish a DID document (public key) to DeDi
 *   3. `POST /keys/resolve`   — resolve a DID document from DeDi
 *
 * SECURITY INVARIANTS:
 *  - GET /keys returns ONLY safe metadata (id, fingerprint, algorithm, label,
 *    type). NEVER returns private key material.
 *  - The publish/resolve endpoints accept and return DID documents, which
 *    by definition contain only public keys. The same recursive
 *    `rejectKeyMaterial()` guard runs on every POST body so a malformed
 *    request that smuggles a PEM private-key block (or a `privateKey` field)
 *    in any nested string is rejected with 400 before it reaches DeDi.
 *  - When DeDi is not configured, publish/resolve return 503 instead of
 *    silently no-op'ing — same fail-closed pattern as the revocation
 *    routes.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { z } from "zod";
import {
  encodeDidWeb,
  generateDidWebDocument,
  generateDidWebDocumentMultiKey,
  didWebVerificationMethodId,
  type JWK,
  type DidWebKeyInput,
} from "@opencred/did";
import { DeDiClientError, DeDiRecordExistsError } from "@opencred/shared";
import type { DeDiClient, KeyRecord } from "@opencred/dedi-client";
import type { Signer } from "@opencred/signing";
import { getActiveSigner } from "../signing/key-manager.js";
import { getConfig } from "../config.js";
import { getDeDiClient } from "../dedi-singleton.js";
import { getLogger } from "../logger.js";
import { rejectKeyMaterial } from "./credentials.js";
import { parseJsonBody } from "../middleware/parse-json.js";
import { applyCacheHeaders, CACHE_PRESETS } from "../middleware/cache-control.js";

const keys = new Hono();

/**
 * Store the did.json in DeDi, best-effort. The key-registry write that
 * preceded this call is the authoritative state change; failing the whole
 * request *after* it succeeded would tell the operator the operation failed
 * when it (mostly) didn't. Instead the response carries
 * `didDocumentStored: false` and the operator can re-run the endpoint —
 * every step is idempotent, so a retry converges.
 */
async function storeDidDocumentBestEffort(
  dediClient: DeDiClient,
  issuerDid: string,
  document: unknown,
  namespace: string | undefined,
  operation: string,
): Promise<boolean> {
  try {
    await dediClient.publishDidDocument(issuerDid, document, namespace);
    return true;
  } catch (err) {
    getLogger().warn(
      {
        issuerDid,
        operation,
        error: err instanceof Error ? err.message : String(err),
      },
      "did.json refresh failed after key-registry update — re-run the endpoint to retry (idempotent)",
    );
    return false;
  }
}

/** Standard 503 body when DeDi is not configured. */
function dediNotConfigured(c: Context) {
  return c.json(
    {
      error: {
        code: "DEDI_NOT_CONFIGURED",
        message:
          "DeDi is not configured. Set OPENCRED_DEDI_BASE_URL, OPENCRED_DEDI_AUTH_TYPE, " +
          "OPENCRED_DEDI_NAMESPACE, and the matching auth secret to enable this endpoint.",
      },
    },
    503,
  );
}

/**
 * Build the active signer's verification method id (the key id used as the
 * `opencred-key-registry` record key). For did:web it's `<did>#key-0`; for
 * did:key the signer's own id already carries the method-specific fragment.
 */
function activeSignerKeyId(signer: Signer, issuerDid: string, isDidWeb: boolean): string {
  return isDidWeb ? didWebVerificationMethodId(issuerDid) : signer.id;
}

/** Build a `KeyRecord` (status `active`) from the active signer's public JWK. */
function buildActiveKeyRecord(
  signer: Signer,
  issuerDid: string,
  isDidWeb: boolean,
  publicKeyJwk: Record<string, unknown>,
): KeyRecord {
  return {
    keyId: activeSignerKeyId(signer, issuerDid, isDidWeb),
    controllerDid: issuerDid,
    algorithm: String(signer.algorithm),
    publicKeyJwk,
    purpose: ["assertionMethod"],
    status: "active",
  };
}

/**
 * Assemble the current did.json for a did:web issuer from its non-revoked
 * key set, de-duplicated by verification method id. The active key is always
 * first; `retainedKeys` carries cleanly-rotated (non-revoked) keys that must
 * stay published so credentials signed by them still resolve.
 */
function assembleDidDocument(
  issuerDid: string,
  activeKey: DidWebKeyInput,
  retainedKeys: DidWebKeyInput[],
) {
  const seen = new Set<string>();
  const ordered: DidWebKeyInput[] = [];
  for (const key of [activeKey, ...retainedKeys]) {
    if (seen.has(key.id)) continue;
    seen.add(key.id);
    ordered.push(key);
  }
  return generateDidWebDocumentMultiKey(issuerDid, ordered);
}

/**
 * Best-effort lookup of a previously-published key's public JWK from DeDi, so
 * a rotated-but-not-revoked key can be re-listed in the regenerated did.json.
 * Returns `null` when the key isn't resolvable (404 / outage / revoked).
 */
async function resolveRetainedKey(
  dediClient: DeDiClient,
  verificationMethod: string,
  namespace: string | undefined,
): Promise<DidWebKeyInput | null> {
  try {
    const record = await dediClient.resolveKey(verificationMethod, namespace);
    if (record.status === "revoked") return null;
    return { id: record.keyId, publicKeyJwk: record.publicKeyJwk as JWK };
  } catch {
    return null;
  }
}

interface KeyDescriptor {
  /** The verification method DID identifier (did:key or did:jwk). */
  id: string;
  /** SHA-256 fingerprint of the public key (hex). */
  fingerprint: string;
  /** Signing algorithm: P-256 | P-384 | Ed25519 | RSA-2048 | RSA-3072 | RSA-4096. */
  algorithm: string;
  /** "software" | "pkcs11" | "os-cert" — where the key lives. */
  type: string;
  /** Whether a certificate chain is bound to this key (e.g. from PFX import). */
  hasCertificateChain: boolean;
  /** User-friendly label, if set via OPENCRED_KEY_LABEL. */
  label?: string;
  /** The configured source — software-file | aws-kms | azure-kv | gcp-kms. */
  source: string;
}

/**
 * GET /keys
 *
 * Returns the key sources currently configured on the server. The response
 * contains only safe identifying metadata; no private key material is ever
 * returned.
 */
keys.get("/keys", (c) => {
  const signer = getActiveSigner();
  const config = getConfig();

  if (!signer) {
    return c.json({
      keys: [],
      message: "No signing key configured. Set OPENCRED_KEY_PATH or a Cloud HSM provider.",
    });
  }

  // Determine the source label without leaking the file path itself.
  const provider = config.OPENCRED_KMS_PROVIDER ?? "none";
  let source = "software-file";
  if (provider === "aws") source = "aws-kms";
  else if (provider === "azure") source = "azure-kv";
  else if (provider === "gcp") source = "gcp-kms";

  const descriptor: KeyDescriptor = {
    id: signer.id,
    fingerprint: signer.metadata.fingerprint,
    algorithm: signer.algorithm,
    type: signer.type,
    hasCertificateChain:
      Array.isArray(signer.metadata.certificateChain) &&
      signer.metadata.certificateChain.length > 0,
    source,
  };

  if (signer.metadata.label) {
    descriptor.label = signer.metadata.label;
  }

  return c.json({ keys: [descriptor] });
});

/**
 * GET /keys/did-document
 *
 * Returns the canonical DID Document the operator should self-host at
 * `https://<domain>/.well-known/did.json` (Path A in docs/concepts/dids.md).
 *
 * **Source preference**:
 *
 *   1. If DeDi is configured AND the DID is already published there, return
 *      the DeDi-persisted document verbatim. That document carries rotation
 *      history (multi-key `verificationMethod[]` with `supersededAt`
 *      timestamps) that the locally-derived document doesn't have.
 *   2. Otherwise — no DeDi, DeDi misconfigured, or DID not yet published —
 *      derive a fresh single-key document from the active signer's
 *      `publicKeyJwk`. This is what `generateDidWebDocument` produces and
 *      what gets auto-published at startup when
 *      `OPENCRED_AUTO_PUBLISH_KEY=true`.
 *
 * `response.source` discriminates between the two — `"dedi"` when read from
 * the registry, `"active-signer"` when derived locally. Operators following
 * Path A only need the JSON body inside `response.document`; the `source`
 * field is informational so they can confirm whether they're getting
 * rotation-aware content.
 *
 * **Limitations**:
 *
 *   - Currently `did:web` only. did:key issuers don't need a self-hosted
 *     `.well-known/did.json` — the DID is its own document by construction.
 *   - Software signers only. KMS-backed signers do not currently expose
 *     `publicKeyJwk` on their metadata (tracked in #635). Returns 400
 *     with a clear hint if the active signer is KMS-backed.
 *
 * No auth required for the JSON content itself — DID Documents are public
 * by construction — but the endpoint sits behind the same API-key
 * middleware as the rest of `/v1/keys/*` so internal endpoints stay
 * consistent. Operators wishing to expose the doc to verifiers should
 * still serve it at `.well-known/did.json` on their domain.
 */
keys.get("/keys/did-document", async (c) => {
  const signer = getActiveSigner();
  const config = getConfig();

  if (!signer) {
    return c.json(
      {
        error: {
          code: "NO_SIGNER",
          message:
            "No signing key loaded. Set OPENCRED_KEY_PATH or a Cloud HSM provider before calling /v1/keys/did-document.",
        },
      },
      503,
    );
  }

  // Derive the issuer DID using the same priority as the credentials route:
  // configured did:web domain wins; otherwise fall back to the signer-derived
  // DID (did:key / did:jwk).
  const issuerDid =
    config.OPENCRED_ISSUER_DID_METHOD === "web" && config.OPENCRED_ISSUER_DOMAIN
      ? encodeDidWeb(config.OPENCRED_ISSUER_DOMAIN)
      : signer.id.split("#")[0]!;

  if (!issuerDid.startsWith("did:web:")) {
    return c.json(
      {
        error: {
          code: "UNSUPPORTED_DID_METHOD",
          message:
            "GET /v1/keys/did-document supports did:web issuers only. did:key DIDs are self-resolving — " +
            "verifiers derive the DID Document from the DID string directly, no .well-known/did.json " +
            "is needed.",
          activeDid: issuerDid,
        },
      },
      400,
    );
  }

  // Path 1: prefer DeDi's stored did.json (the `did-documents` registry).
  // It is the authoritative current document — it carries every non-revoked
  // key (multi-key `verificationMethod[]`) after rotation/revocation. Falls
  // through on 404 (DID not yet stored there); any other DeDi error is
  // logged at warn level so the operator can debug but doesn't block the
  // response.
  const dediClient = getDeDiClient();
  if (dediClient) {
    try {
      const record = await dediClient.resolveDidDocument(issuerDid);
      if (record.document) {
        return c.json({ did: issuerDid, document: record.document, source: "dedi" });
      }
    } catch (err) {
      if (err instanceof DeDiClientError && err.statusCode === 404) {
        // Expected: DID not yet stored in DeDi. Fall through to derivation.
      } else {
        // statusCode is broken out from the message so operators can
        // distinguish auth (401/403) from server errors (5xx) from network
        // failures (no statusCode) at a glance in structured logs.
        getLogger().warn(
          {
            err: err instanceof Error ? err.message : String(err),
            statusCode: err instanceof DeDiClientError ? err.statusCode : undefined,
            issuerDid,
          },
          "GET /v1/keys/did-document: DeDi lookup failed; falling back to active-signer-derived document",
        );
      }
    }
  }

  // Path 2: derive a single-key document from the active signer's public JWK.
  // Mirrors what generateDidWebDocument emits for the auto-publish path so the
  // self-hosted document matches what verifiers see via DeDi after first
  // publish.
  const publicKeyJwk = signer.metadata.publicKeyJwk;
  if (!publicKeyJwk) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message:
            "Active signer does not expose publicKeyJwk on its metadata. " +
            "GET /v1/keys/did-document requires a software-backed signer; KMS-backed signers " +
            "(AWS KMS / Azure KV / GCP KMS) do not currently surface the JWK — track issue #635.",
          signerType: signer.type,
        },
      },
      400,
    );
  }

  const document = generateDidWebDocument(issuerDid, publicKeyJwk as JWK);
  return c.json({ did: issuerDid, document, source: "active-signer" });
});

// --- DeDi per-key registry + DID documents ---
//
// Signing keys are pushed into and pulled from the DeDi
// `opencred-key-registry` (one record per key, status active/rotated/revoked).
// For did:web issuers who opt into DeDi-hosting, the assembled did.json is
// also stored in the `did-documents` registry. Lets verifiers resolve an
// issuer's key status — and, when the domain is unreachable, the did.json —
// without a separate DID registrar.

const publishKeySchema = z.object({
  /**
   * Optional namespace override. When omitted, DeDi's `defaultNamespace`
   * (configured via `OPENCRED_DEDI_NAMESPACE`) is used.
   */
  namespace: z.string().optional(),
  /**
   * Whether to also store the assembled did.json in the `did-documents`
   * registry (did:web only). Defaults to `OPENCRED_DEDI_HOST_DID_DOC`.
   */
  hostDidDocument: z.boolean().optional(),
});

const rotateKeySchema = z.object({
  /**
   * The verification method of the key being retired, e.g.
   * `did:web:issuer.example.org#key-0`. Flipped to `rotated` in the key
   * registry and kept in the regenerated did.json so credentials it signed
   * still resolve. Omit on a first publish (nothing to retire yet).
   */
  previousVerificationMethod: z.string().optional(),
  namespace: z.string().optional(),
  hostDidDocument: z.boolean().optional(),
});

const revokeKeySchema = z.object({
  /** The verification method of the key to revoke. */
  verificationMethod: z.string().min(1),
  namespace: z.string().optional(),
  hostDidDocument: z.boolean().optional(),
});

const resolveKeySchema = z.object({
  /** The verification method (key id) to look up in the key registry. */
  verificationMethod: z.string().min(1),
  namespace: z.string().optional(),
});

/**
 * POST /keys/publish
 *
 * Publish the active signer's signing key to the DeDi `opencred-key-registry`
 * (status `active`). For did:web issuers, optionally also store the assembled
 * did.json in the `did-documents` registry.
 *
 * The server only ever publishes its OWN public key — no key material is
 * accepted from the request body (CLAUDE.md rule 1).
 *
 * Request body:
 *   { namespace?: string, hostDidDocument?: boolean }
 *
 * Response (200):
 *   { published: true, recordName: string, namespace: string,
 *     keyId: string, didDocumentStored: boolean }
 */
keys.post("/keys/publish", async (c) => {
  const body = await parseJsonBody(c);
  // SECURITY: defense-in-depth — recursively reject any nested PEM block or
  // forbidden key field before anything leaves the server. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = publishKeySchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) return dediNotConfigured(c);

  const signer = getActiveSigner();
  if (!signer) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message:
            "No signing key configured. Set OPENCRED_KEY_PATH or a Cloud HSM provider before calling /v1/keys/publish.",
        },
      },
      400,
    );
  }

  const config = getConfig();
  const isDidWeb =
    config.OPENCRED_ISSUER_DID_METHOD === "web" && !!config.OPENCRED_ISSUER_DOMAIN;
  const issuerDid = isDidWeb
    ? encodeDidWeb(config.OPENCRED_ISSUER_DOMAIN!)
    : signer.id.split("#")[0]!;

  const publicKeyJwk = signer.metadata.publicKeyJwk;
  if (!publicKeyJwk) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message:
            "Active signer does not expose publicKeyJwk on its metadata. Publishing requires a " +
            "software-backed signer; KMS-backed signers do not currently surface the JWK (#635).",
          signerType: signer.type,
        },
      },
      400,
    );
  }

  const keyRecord = buildActiveKeyRecord(signer, issuerDid, isDidWeb, publicKeyJwk);
  const result = await dediClient.publishKey(keyRecord, parsed.namespace);

  const hostDidDoc = isDidWeb && (parsed.hostDidDocument ?? config.OPENCRED_DEDI_HOST_DID_DOC);
  let didDocumentStored = false;
  if (hostDidDoc) {
    const document = generateDidWebDocument(issuerDid, publicKeyJwk as JWK);
    didDocumentStored = await storeDidDocumentBestEffort(
      dediClient,
      issuerDid,
      document,
      parsed.namespace,
      "publish",
    );
  }
  return c.json({ ...result, keyId: keyRecord.keyId, didDocumentStored });
});

/**
 * POST /keys/rotate
 *
 * Clean key rotation for a did:web issuer. The operator deploys a NEW signing
 * key (the active signer), then calls this endpoint:
 *
 *   1. Publishes the new key to `opencred-key-registry` (status `active`).
 *   2. Flips the previous key (`previousVerificationMethod`) to `rotated`.
 *      Credentials signed by it stay valid — a clean rotation is not a
 *      compromise — and the key is kept in the regenerated did.json.
 *   3. Regenerates and re-stores the did.json (active + rotated keys).
 *
 * Scope: did:web only. did:key rotation produces a new DID — issuers should
 * regenerate their key instead. Sits under /v1/keys/ (WRITE_PREFIXES), so
 * OPENCRED_READ_ONLY=true gates it to 403 automatically.
 */
keys.post("/keys/rotate", async (c) => {
  const body = await parseJsonBody(c);
  rejectKeyMaterial(body);
  const parsed = rotateKeySchema.parse(body);

  const signer = getActiveSigner();
  if (!signer) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message:
            "No signing key configured. Set OPENCRED_KEY_PATH or a Cloud HSM provider before calling /v1/keys/rotate.",
        },
      },
      400,
    );
  }

  const config = getConfig();
  const issuerDid =
    config.OPENCRED_ISSUER_DID_METHOD === "web" && config.OPENCRED_ISSUER_DOMAIN
      ? encodeDidWeb(config.OPENCRED_ISSUER_DOMAIN)
      : signer.id.split("#")[0]!;
  if (!issuerDid.startsWith("did:web:")) {
    return c.json(
      {
        error: {
          code: "KEY_METHOD_MISMATCH",
          message:
            "/v1/keys/rotate supports did:web issuers only. did:key rotation produces a new DID — " +
            "regenerate the signing key instead (the new key derives a new did:key automatically).",
          activeDid: issuerDid,
        },
      },
      400,
    );
  }

  const publicKeyJwk = signer.metadata.publicKeyJwk;
  if (!publicKeyJwk) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message:
            "Active signer does not expose publicKeyJwk on its metadata. Rotation requires a " +
            "software-backed signer; KMS-backed signers are not yet supported by /v1/keys/rotate.",
          signerType: signer.type,
        },
      },
      400,
    );
  }

  const dediClient = getDeDiClient();
  if (!dediClient) return dediNotConfigured(c);

  const newKeyRecord = buildActiveKeyRecord(signer, issuerDid, true, publicKeyJwk);

  // Publish the new key (idempotent: a re-run after a transient failure sees
  // the record already there, which is fine).
  try {
    await dediClient.publishKey(newKeyRecord, parsed.namespace);
  } catch (err) {
    if (!(err instanceof DeDiRecordExistsError)) throw err;
  }

  // Retire the previous key and keep it (non-revoked) in the regenerated
  // did.json so older credentials still resolve.
  let retired: Awaited<ReturnType<DeDiClient["setKeyStatus"]>> | null = null;
  let retainedKeys: DidWebKeyInput[] = [];
  if (parsed.previousVerificationMethod) {
    retired = await dediClient.setKeyStatus(
      parsed.previousVerificationMethod,
      "rotated",
      parsed.namespace,
    );
    const retained = await resolveRetainedKey(
      dediClient,
      parsed.previousVerificationMethod,
      parsed.namespace,
    );
    if (retained) retainedKeys = [retained];
  }

  const hostDidDoc = parsed.hostDidDocument ?? config.OPENCRED_DEDI_HOST_DID_DOC;
  let didDocumentStored = false;
  if (hostDidDoc) {
    const document = assembleDidDocument(
      issuerDid,
      { id: newKeyRecord.keyId, publicKeyJwk: publicKeyJwk as JWK },
      retainedKeys,
    );
    didDocumentStored = await storeDidDocumentBestEffort(
      dediClient,
      issuerDid,
      document,
      parsed.namespace,
      "rotate",
    );
  }

  return c.json({
    rotated: true,
    did: issuerDid,
    currentKeyId: newKeyRecord.keyId,
    retired,
    didDocumentStored,
  });
});

/**
 * POST /keys/revoke
 *
 * Revoke a signing key — flips its `opencred-key-registry` status to
 * `revoked`. A revoked key may be compromised, so verifiers reject EVERY
 * credential it signed (top-level `REVOKED`), regardless of when they were
 * issued. This is the per-key counterpart to per-credential revocation.
 *
 * When DeDi-hosting is enabled and the revoked key is not the active signer's
 * own key, the did.json is regenerated from the active signer's current key
 * (dropping the revoked key) and re-stored. (A headless server doesn't track
 * the full historical key set; the authoritative reject is the `revoked`
 * status flip, not the did.json contents.)
 */
keys.post("/keys/revoke", async (c) => {
  const body = await parseJsonBody(c);
  rejectKeyMaterial(body);
  const parsed = revokeKeySchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) return dediNotConfigured(c);

  const result = await dediClient.setKeyStatus(parsed.verificationMethod, "revoked", parsed.namespace);

  // Best-effort did.json refresh (did:web only). Only when the active signer
  // is still a valid, non-revoked key — never republish a document built
  // around the key we just revoked.
  const config = getConfig();
  const signer = getActiveSigner();
  const hostDidDoc = parsed.hostDidDocument ?? config.OPENCRED_DEDI_HOST_DID_DOC;
  let didDocumentStored = false;
  if (hostDidDoc && signer) {
    const isDidWeb =
      config.OPENCRED_ISSUER_DID_METHOD === "web" && !!config.OPENCRED_ISSUER_DOMAIN;
    const issuerDid = isDidWeb ? encodeDidWeb(config.OPENCRED_ISSUER_DOMAIN!) : "";
    const publicKeyJwk = signer.metadata.publicKeyJwk;
    const activeKeyId = isDidWeb ? didWebVerificationMethodId(issuerDid) : signer.id;
    if (isDidWeb && publicKeyJwk && activeKeyId !== parsed.verificationMethod) {
      const document = generateDidWebDocument(issuerDid, publicKeyJwk as JWK);
      didDocumentStored = await storeDidDocumentBestEffort(
        dediClient,
        issuerDid,
        document,
        parsed.namespace,
        "revoke",
      );
    }
  }

  return c.json({ revoked: true, ...result, didDocumentStored });
});

/**
 * POST /keys/resolve
 *
 * Resolve a signing key's record from the DeDi `opencred-key-registry`.
 *
 * Request body:
 *   { verificationMethod: string, namespace?: string }
 *
 * Response (200): the {@link KeyRecord} —
 *   { keyId, controllerDid, algorithm, publicKeyJwk, purpose, status, proof? }
 *
 * **Breaking change.** Prior releases keyed this endpoint by `did` and
 * returned a DID-document record (`{ did, document?, keyStatus }`). It now
 * keys by `verificationMethod` and returns the per-key record. did.json is
 * served separately via `GET /v1/keys/did-document`.
 *
 * POST (not GET) is used so verification methods containing colons (the
 * canonical `did:web:host:path#key-0` form) don't have to be URL-encoded.
 */
keys.post("/keys/resolve", async (c) => {
  const body = await parseJsonBody(c);
  rejectKeyMaterial(body);
  const parsed = resolveKeySchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) return dediNotConfigured(c);

  const record = await dediClient.resolveKey(parsed.verificationMethod, parsed.namespace);
  // Cache headers + ETag. Key resolution is idempotent and content-identified.
  // `didDocumentPrivate` (private, max-age=60) mirrors POST /credentials/verify
  // so a shared CDN can't serve one tenant's record to another. The 304 path
  // short-circuits on a matching `If-None-Match`.
  const notModified = applyCacheHeaders(c, record, CACHE_PRESETS.didDocumentPrivate);
  if (notModified) return notModified;
  return c.json(record);
});

/**
 * GET /keys/resolve?verificationMethod=...&namespace=...
 *
 * Read-only, idempotent, CDN-cacheable surface of {@link `POST /keys/resolve`}.
 * The query string is URL-decoded by Hono before reaching `c.req.query`.
 */
keys.get("/keys/resolve", async (c) => {
  const verificationMethod = c.req.query("verificationMethod");
  if (!verificationMethod) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "`verificationMethod` query parameter is required",
        },
      },
      400,
    );
  }
  const namespace = c.req.query("namespace");
  const dediClient = getDeDiClient();
  if (!dediClient) return dediNotConfigured(c);

  const record = await dediClient.resolveKey(verificationMethod, namespace);
  const notModified = applyCacheHeaders(c, record, CACHE_PRESETS.didDocument);
  if (notModified) return notModified;
  return c.json(record);
});

export { keys };
