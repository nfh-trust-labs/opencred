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
  generateDidWebDocumentMultiKey,
  didWebVerificationMethodIdForIndex,
  importDidWebDocument,
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
 * `opencred-key-registry` record key). For did:web it's `<did>#key-<index>`
 * (the configured `OPENCRED_DIDWEB_KEY_INDEX`); for did:key the signer's own
 * id already carries the method-specific fragment.
 */
function activeSignerKeyId(
  signer: Signer,
  issuerDid: string,
  isDidWeb: boolean,
  keyIndex: number,
): string {
  return isDidWeb ? didWebVerificationMethodIdForIndex(issuerDid, keyIndex) : signer.id;
}

/** Build a `KeyRecord` (status `active`) from the active signer's public JWK. */
function buildActiveKeyRecord(
  signer: Signer,
  issuerDid: string,
  isDidWeb: boolean,
  publicKeyJwk: Record<string, unknown>,
  keyIndex: number,
): KeyRecord {
  return {
    keyId: activeSignerKeyId(signer, issuerDid, isDidWeb, keyIndex),
    controllerDid: issuerDid,
    algorithm: String(signer.algorithm),
    publicKeyJwk,
    purpose: ["assertionMethod"],
    status: "active",
  };
}

/**
 * Load the issuer's current did.json and import it as a stateless key set.
 *
 * The rotate/revoke endpoints hold NO local rotation history — the authoritative
 * existing key set comes entirely from the current did.json. This prefers the
 * document the operator passed in the request body (`provided`, e.g. pasted from
 * their domain or DeDi); otherwise it fetches the DeDi-hosted document from the
 * `did-documents` registry. Returns `null` when neither is available, so the
 * caller can fail closed (rotate) or skip the did.json refresh (revoke) rather
 * than silently regenerate a document missing the issuer's older keys.
 */
async function loadCurrentDidDocument(
  dediClient: DeDiClient,
  issuerDid: string,
  provided: Record<string, unknown> | undefined,
  namespace: string | undefined,
): Promise<ReturnType<typeof importDidWebDocument> | null> {
  if (provided) {
    return importDidWebDocument(provided);
  }
  try {
    const record = await dediClient.resolveDidDocument(issuerDid, namespace);
    if (record.document) return importDidWebDocument(record.document);
  } catch {
    // 404 / outage — no DeDi-hosted document to import; caller decides.
  }
  return null;
}

/** Map an imported key set to the generator's `DidWebKeyInput[]`, preserving revoked status. */
function carryForwardKeys(keys: ReturnType<typeof importDidWebDocument>["keys"]): DidWebKeyInput[] {
  return keys.map((key) => ({
    id: key.id,
    publicKeyJwk: key.publicKeyJwk,
    revoked: key.revoked,
  }));
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

  const activeKeyId = activeSignerKeyId(signer, issuerDid, true, config.OPENCRED_DIDWEB_KEY_INDEX);
  const document = generateDidWebDocumentMultiKey(issuerDid, [
    { id: activeKeyId, publicKeyJwk: publicKeyJwk as JWK },
  ]);
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
   * The sequential index of the NEW key, e.g. `1`. The operator chooses this
   * explicitly (OpenCred never guesses) and it must not already be taken in the
   * current did.json — the new key is published at `did:web:<domain>#key-<n>`.
   */
  newKeyIndex: z.number().int().min(0),
  /**
   * The verification method of the key being retired, e.g.
   * `did:web:issuer.example.org#key-0`. Flipped to `rotated` in the key
   * registry and kept in the regenerated did.json (relationships included) so
   * credentials it signed still resolve. Omit only when adding a key without
   * retiring one.
   */
  previousVerificationMethod: z.string().optional(),
  /**
   * The issuer's CURRENT did.json, imported as a whole. This is the stateless
   * source of truth for the existing key set + taken indices. When omitted, the
   * server falls back to the DeDi-hosted document (`did-documents` registry);
   * if neither is available the request is rejected so older keys are never
   * silently dropped.
   */
  currentDidDocument: z.record(z.unknown()).optional(),
  namespace: z.string().optional(),
  hostDidDocument: z.boolean().optional(),
});

const revokeKeySchema = z.object({
  /** The verification method of the key to revoke. */
  verificationMethod: z.string().min(1),
  /**
   * The issuer's CURRENT did.json (imported as a whole). Used to regenerate the
   * document so the revoked key drops out of every verification relationship
   * while STAYING in `verificationMethod[]`. When omitted, the DeDi-hosted
   * document is used; if neither is available the registry status flip is still
   * authoritative and the did.json refresh is skipped.
   */
  currentDidDocument: z.record(z.unknown()).optional(),
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
  const isDidWeb = config.OPENCRED_ISSUER_DID_METHOD === "web" && !!config.OPENCRED_ISSUER_DOMAIN;
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

  const keyRecord = buildActiveKeyRecord(
    signer,
    issuerDid,
    isDidWeb,
    publicKeyJwk,
    config.OPENCRED_DIDWEB_KEY_INDEX,
  );
  const result = await dediClient.publishKey(keyRecord, parsed.namespace);

  const hostDidDoc = isDidWeb && (parsed.hostDidDocument ?? config.OPENCRED_DEDI_HOST_DID_DOC);
  let didDocumentStored = false;
  if (hostDidDoc) {
    const document = generateDidWebDocumentMultiKey(issuerDid, [
      { id: keyRecord.keyId, publicKeyJwk: publicKeyJwk as JWK },
    ]);
    await dediClient.publishDidDocument(issuerDid, document, parsed.namespace);
    didDocumentStored = true;
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

  // The operator explicitly states which #key-<n> the new key takes.
  const newVerificationMethod = didWebVerificationMethodIdForIndex(issuerDid, parsed.newKeyIndex);

  // Import the current did.json (operator-provided or DeDi-hosted) — the
  // stateless source of truth for the existing key set + taken indices.
  const current = await loadCurrentDidDocument(
    dediClient,
    issuerDid,
    parsed.currentDidDocument,
    parsed.namespace,
  );
  if (!current) {
    return c.json(
      {
        error: {
          code: "NO_CURRENT_DOCUMENT",
          message:
            "Rotation needs the issuer's current did.json to carry existing keys forward. " +
            "Provide it as `currentDidDocument`, or enable DeDi-hosting so it can be fetched " +
            "from the did-documents registry.",
        },
      },
      400,
    );
  }
  if (current.did !== issuerDid) {
    return c.json(
      {
        error: {
          code: "DID_MISMATCH",
          message: `currentDidDocument is for ${current.did}, but this issuer is ${issuerDid}.`,
        },
      },
      400,
    );
  }
  if (current.usedIndices.includes(parsed.newKeyIndex)) {
    return c.json(
      {
        error: {
          code: "KEY_INDEX_TAKEN",
          message:
            `#key-${String(parsed.newKeyIndex)} is already present in the current did.json. ` +
            `The next free index is ${String(current.maxKeyIndex + 1)}.`,
          usedIndices: current.usedIndices,
        },
      },
      409,
    );
  }

  // Publish the new active key at #key-<newKeyIndex> (idempotent on re-run).
  const newKeyRecord: KeyRecord = {
    keyId: newVerificationMethod,
    controllerDid: issuerDid,
    algorithm: String(signer.algorithm),
    publicKeyJwk,
    purpose: ["assertionMethod"],
    status: "active",
  };
  try {
    await dediClient.publishKey(newKeyRecord, parsed.namespace);
  } catch (err) {
    if (!(err instanceof DeDiRecordExistsError)) throw err;
  }

  // Retire the previous key (flip to `rotated`). It stays in the regenerated
  // did.json's relationships — a clean rotation does not invalidate the
  // credentials it signed.
  let retired: Awaited<ReturnType<DeDiClient["setKeyStatus"]>> | null = null;
  if (parsed.previousVerificationMethod) {
    retired = await dediClient.setKeyStatus(
      parsed.previousVerificationMethod,
      "rotated",
      parsed.namespace,
    );
  }

  // Regenerate the did.json: carry every existing key forward (preserving each
  // one's revoked status) and append the new active key. Returned in the
  // response so an operator self-hosting at their domain can re-publish it.
  const keySet: DidWebKeyInput[] = [
    ...carryForwardKeys(current.keys),
    { id: newVerificationMethod, publicKeyJwk: publicKeyJwk as JWK },
  ];
  const document = generateDidWebDocumentMultiKey(issuerDid, keySet);

  const hostDidDoc = parsed.hostDidDocument ?? config.OPENCRED_DEDI_HOST_DID_DOC;
  let didDocumentStored = false;
  if (hostDidDoc) {
    await dediClient.publishDidDocument(issuerDid, document, parsed.namespace);
    didDocumentStored = true;
  }

  return c.json({
    rotated: true,
    did: issuerDid,
    currentKeyId: newVerificationMethod,
    newKeyIndex: parsed.newKeyIndex,
    retired,
    didDocument: document,
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
 * For did:web issuers with DeDi-hosting, the did.json is regenerated so the
 * revoked key drops out of every verification relationship (`assertionMethod`,
 * …) while STAYING in `verificationMethod[]`. Keeping it dereferenceable lets a
 * verifier resolve the signing key and then report a precise `REVOKED` (via the
 * registry status) rather than "unresolvable"; dropping it from relationships
 * de-authorizes it for W3C-only verifiers (W3C DID Core §5.3). The registry
 * status flip is always authoritative — the did.json refresh is best-effort and
 * skipped if the current document can't be obtained or revoking would leave no
 * active key.
 */
keys.post("/keys/revoke", async (c) => {
  const body = await parseJsonBody(c);
  rejectKeyMaterial(body);
  const parsed = revokeKeySchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) return dediNotConfigured(c);

  const result = await dediClient.setKeyStatus(
    parsed.verificationMethod,
    "revoked",
    parsed.namespace,
  );

  const config = getConfig();
  const isDidWeb = config.OPENCRED_ISSUER_DID_METHOD === "web" && !!config.OPENCRED_ISSUER_DOMAIN;
  const hostDidDoc = parsed.hostDidDocument ?? config.OPENCRED_DEDI_HOST_DID_DOC;
  let didDocumentStored = false;
  let document: ReturnType<typeof generateDidWebDocumentMultiKey> | null = null;

  if (isDidWeb && hostDidDoc) {
    const issuerDid = encodeDidWeb(config.OPENCRED_ISSUER_DOMAIN!);
    const current = await loadCurrentDidDocument(
      dediClient,
      issuerDid,
      parsed.currentDidDocument,
      parsed.namespace,
    );
    if (current) {
      // Mark the target key revoked; keep every key in verificationMethod[].
      const keySet: DidWebKeyInput[] = current.keys.map((key) => ({
        id: key.id,
        publicKeyJwk: key.publicKeyJwk,
        revoked: key.revoked || key.id === parsed.verificationMethod,
      }));
      if (keySet.some((key) => !key.revoked)) {
        document = generateDidWebDocumentMultiKey(issuerDid, keySet);
        await dediClient.publishDidDocument(issuerDid, document, parsed.namespace);
        didDocumentStored = true;
      } else {
        getLogger().warn(
          { issuerDid, verificationMethod: parsed.verificationMethod },
          "Revoke would leave no active key; did.json not regenerated (registry status is authoritative).",
        );
      }
    }
  }

  return c.json({ revoked: true, ...result, didDocument: document, didDocumentStored });
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
