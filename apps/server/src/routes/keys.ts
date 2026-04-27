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
import { getActiveSigner } from "../signing/key-manager.js";
import { getConfig } from "../config.js";
import { getDeDiClient } from "../dedi-singleton.js";
import { rejectKeyMaterial } from "./credentials.js";

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
   */
  document: z.record(z.unknown()),
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
  const body = await c.req.json();
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

/**
 * POST /keys/resolve
 *
 * Resolve a DID document from the DeDi public-key registry.
 *
 * Request body:
 *   { did: string, namespace?: string }
 *
 * Response (200):
 *   { did: string, document: object, resolvedAt: string }
 *
 * POST (not GET) is used so that DIDs containing colons (e.g.
 * `did:web:example.org:users:alice`) and other path-unfriendly characters
 * don't have to be URL-encoded by callers. Mirrors the existing
 * `POST /credentials/revocation-status` shape.
 */
keys.post("/keys/resolve", async (c) => {
  const body = await c.req.json();
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
  return c.json(record);
});

export { keys };
