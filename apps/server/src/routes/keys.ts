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
import { z } from "zod";
import { encodeDidWeb, generateDidWebDocument, type JWK } from "@opencred/did";
import { DeDiClientError } from "@opencred/shared";
import { getActiveSigner } from "../signing/key-manager.js";
import { getConfig } from "../config.js";
import { getDeDiClient } from "../dedi-singleton.js";
import { getLogger } from "../logger.js";
import { rejectKeyMaterial } from "./credentials.js";
import { parseJsonBody } from "../middleware/parse-json.js";
import { applyCacheHeaders, CACHE_PRESETS } from "../middleware/cache-control.js";

const keys = new Hono();

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

  // Path 1: prefer DeDi's record (carries rotation history). Falls through
  // on 404 (DID not yet published there); any other DeDi error is logged
  // at warn level so the operator can debug but doesn't block the response.
  const dediClient = getDeDiClient();
  if (dediClient) {
    try {
      const record = await dediClient.resolveDID(issuerDid);
      if (record.document) {
        return c.json({ did: issuerDid, document: record.document, source: "dedi" });
      }
    } catch (err) {
      if (err instanceof DeDiClientError && err.statusCode === 404) {
        // Expected: DID not yet on DeDi. Fall through to local derivation.
      } else {
        getLogger().warn(
          {
            err: err instanceof Error ? err.message : String(err),
            issuerDid,
          },
          "GET /v1/keys/did-document: DeDi lookup failed; falling back to active-signer-derived document",
        );
      }
    }
  }

  // Path 2: derive from the active signer's public JWK. Mirrors what
  // generateDidWebDocument emits for the auto-publish path so the
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

// --- DeDi public-key registry ---
//
// DID documents (public keys + verification methods) are pushed into and
// pulled from the DeDi `public_key_registry`. Lets verifiers resolve an
// issuer's keys without a separate DID registrar.

const publishKeySchema = z.object({
  /** The DID this document belongs to (e.g. `did:web:example.org`). */
  did: z.string().min(1),
  /**
   * The full DID document. By the W3C DID Core spec this is a JSON object
   * carrying `verificationMethod`, `assertionMethod`, etc. — all of which
   * describe public keys. Private keys must NEVER appear here; the
   * recursive `rejectKeyMaterial()` walk over the request body enforces
   * that as a defense-in-depth check.
   *
   * **Optional at this layer.** The schema accepts publish requests
   * without a `document` for did:key issuers — the adapter
   * (`packages/dedi-client/src/adapter/client.ts:publishDID`) drops the
   * document for did:key anyway, since did:key documents are derivable
   * from the DID itself. For did:web, the adapter still enforces that
   * `document` is required (otherwise there's nothing to cache). Making
   * the route schema optional lets the bootcamp Postman collection ship
   * a minimal `{"did": "{{issuerDid}}"}` body for did:key publish demos
   * without contorting around a 400 from Zod.
   */
  document: z.record(z.unknown()).optional(),
  /**
   * Optional namespace override. When omitted, DeDi's `defaultNamespace`
   * (configured via `OPENCRED_DEDI_NAMESPACE`) is used.
   */
  namespace: z.string().optional(),
});

const resolveKeySchema = z.object({
  /** The DID to look up in the public-key registry. */
  did: z.string().min(1),
  namespace: z.string().optional(),
});

/**
 * POST /keys/publish
 *
 * Publish a DID document to the DeDi public-key registry.
 *
 * Request body:
 *   { did: string, document: object, namespace?: string }
 *
 * Response (200):
 *   { published: true, recordName: string, namespace: string }
 *
 * Response (503): DeDi not configured.
 */
keys.post("/keys/publish", async (c) => {
  const body = await parseJsonBody(c);
  // SECURITY: defense-in-depth — recursively reject any nested PEM block or
  // forbidden key field before the document leaves the server. See
  // CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = publishKeySchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) {
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

  const result = await dediClient.publishDID(parsed.did, parsed.document, parsed.namespace);
  return c.json(result);
});

const rotateKeySchema = z.object({
  namespace: z.string().optional(),
});

/**
 * POST /keys/rotate
 *
 * Rotate the active signer's did:web key inside its DID Document.
 * The DID stays stable; the new key is appended to verificationMethod[]
 * and the prior current key is marked supersededAt. See
 * docs/spikes/spike-619-did-web-rotation.md for the design.
 *
 * Scope: did:web only. did:key rotation produces a new DID — issuers
 * should regenerate their key instead. The endpoint sits under
 * /v1/keys/ which is in WRITE_PREFIXES, so OPENCRED_READ_ONLY=true
 * gates it to 403 READ_ONLY_MODE automatically.
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

  // Derive the issuer DID from the signer (signer.id is the verification
  // method ID, e.g. did:web:issuer.example.org#key-1). Strip the fragment.
  const issuerDid = signer.id.split("#")[0]!;
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
  if (!dediClient) {
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

  const result = await dediClient.rotateDIDWeb(issuerDid, publicKeyJwk, parsed.namespace);
  return c.json(result);
});

/**
 * POST /keys/resolve
 *
 * Resolve a DID document from the DeDi public-key registry.
 *
 * Request body:
 *   { did: string, namespace?: string }
 *
 * Response (200):
 *   { did: string, document?: object, keyStatus: "current" | "rotated" }
 *
 * `document` is omitted from the response when the DID is `did:key:` —
 * the verifier derives the document from the DID itself via the
 * canonical did:key resolution algorithm. For `did:web` records the
 * cached domain-hosted document is returned. `keyStatus` is `"current"`
 * by default and flipped to `"rotated"` after the issuer rotates keys.
 *
 * **Breaking change** (PR-3 of the DeDi client refactor): prior to this
 * release the response carried `resolvedAt: string` and optionally
 * `metadata` / `supersededBy`. Downstream consumers must update to read
 * the new shape; `resolvedAt` is no longer surfaced (the DeDi envelope's
 * `updated_at` is canonical if a precise on-server timestamp is needed
 * in a future iteration).
 *
 * POST (not GET) is used so that DIDs containing colons (e.g.
 * `did:web:example.org:users:alice`) and other path-unfriendly characters
 * don't have to be URL-encoded by callers. Mirrors the existing
 * `POST /credentials/revocation-status` shape.
 */
keys.post("/keys/resolve", async (c) => {
  const body = await parseJsonBody(c);
  rejectKeyMaterial(body);
  const parsed = resolveKeySchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) {
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

  const record = await dediClient.resolveDID(parsed.did, parsed.namespace);
  // Cache headers + ETag (issue #446 Tier 3 #9, follow-up #586).
  // DID-document resolution is idempotent and the record is identified by
  // its content, so a downstream service-worker / in-process LRU can dedupe
  // rapid re-reads. We use the `didDocumentPrivate` preset (private,
  // max-age=60) here — mirroring `POST /credentials/verify` — so a shared
  // CDN cannot accidentally cache one tenant's resolution and serve it to
  // another. Callers that want a publicly-cacheable response should use
  // `GET /keys/resolve?did=...` instead, which emits the public preset.
  // The 304 path still short-circuits on a matching `If-None-Match`.
  const notModified = applyCacheHeaders(c, record, CACHE_PRESETS.didDocumentPrivate);
  if (notModified) return notModified;
  return c.json(record);
});

/**
 * GET /keys/resolve?did=...&namespace=...
 *
 * Read-only, idempotent surface of {@link `POST /keys/resolve`} suitable for
 * caching at the CDN tier. DIDs whose serialization contains characters that
 * an L7 proxy might choke on (the canonical `did:web:host:path` form has
 * colons that some intermediates reject) are still resolvable via the POST
 * surface — this GET handler is the cacheable companion, not a replacement.
 *
 * The query string is URL-decoded by Hono before reaching `c.req.query`.
 * Cache headers + ETag are applied the same way as the POST variant.
 */
keys.get("/keys/resolve", async (c) => {
  const did = c.req.query("did");
  if (!did) {
    return c.json(
      { error: { code: "VALIDATION_ERROR", message: "`did` query parameter is required" } },
      400,
    );
  }
  const namespace = c.req.query("namespace");
  const dediClient = getDeDiClient();
  if (!dediClient) {
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
  const record = await dediClient.resolveDID(did, namespace);
  const notModified = applyCacheHeaders(c, record, CACHE_PRESETS.didDocument);
  if (notModified) return notModified;
  return c.json(record);
});

export { keys };
