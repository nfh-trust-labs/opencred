/**
 * Revocation hash computation endpoints.
 *
 * POST /credentials/revocation-hash       — compute a single revocation hash
 * POST /credentials/revocation-hash/batch — compute batch revocation hashes
 *
 * Prefers the hash embedded in `credentialStatus.id` (what the issuer
 * committed to at signing time) and falls back to a JCS-canonical SHA-256 of
 * the whole credential for credentials issued by other implementations. See
 * `resolveRevocationHash` in `@opencred/crypto` — issuance, verification, and
 * revocation-submit MUST all agree on this hash.
 */

import { Hono } from "hono";
import { z } from "zod";
import { resolveRevocationHash } from "@opencred/crypto";
import { rejectKeyMaterial } from "./credentials.js";
import { getDeDiClient } from "../dedi-singleton.js";
import { revocationsPublishedTotal } from "../metrics.js";
import { parseJsonBody } from "../middleware/parse-json.js";
import { driveRevocationToLive } from "../revocation-worker.js";
import { getLogger } from "../logger.js";
import { DeDiClientError } from "@opencred/shared";

const revocation = new Hono();

const singleHashSchema = z.object({
  credential: z.record(z.unknown()),
});

const batchHashSchema = z.object({
  credentials: z.array(z.record(z.unknown())),
});

revocation.post("/credentials/revocation-hash", async (c) => {
  const body = await parseJsonBody(c);
  // SECURITY: defense-in-depth — no route accepts key material. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = singleHashSchema.parse(body);
  const hash = resolveRevocationHash(parsed.credential);
  // PRD §7.3 specifies `revocationHash` as the canonical field name.
  // `hash` is retained as an alias for one release for backwards
  // compatibility with clients that shipped against the pre-rename shape.
  return c.json({ revocationHash: hash, hash });
});

revocation.post("/credentials/revocation-hash/batch", async (c) => {
  const body = await parseJsonBody(c);
  // SECURITY: defense-in-depth — no route accepts key material. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = batchHashSchema.parse(body);

  const entries = parsed.credentials.map((credential, index) => {
    const hash = resolveRevocationHash(credential);
    // Pull credentialId from VC.id when present; fall back to a stable
    // positional token so clients can correlate responses with input rows.
    const vcId = typeof credential["id"] === "string" ? (credential["id"] as string) : null;
    return {
      credentialId: vcId ?? `index:${index}`,
      revocationHash: hash,
      index,
      hash,
    };
  });

  return c.json({
    // PRD §7.3 canonical shape.
    revocationHashes: entries.map(({ credentialId, revocationHash }) => ({
      credentialId,
      revocationHash,
    })),
    // Legacy alias — retained for one release.
    hashes: entries.map(({ index, hash }) => ({ index, hash })),
  });
});

// --- Revoke endpoint (publishes to DeDi) ---

const revokeSchema = z
  .object({
    credential: z.record(z.unknown()).optional(),
    hash: z
      .string()
      .length(64)
      .regex(/^[a-f0-9]+$/)
      .optional(),
    namespace: z.string().optional(),
    /** Optional reason (per DeDi canonical revoke schema https://dedi.global/revoke.json). */
    reason: z.string().optional(),
  })
  .refine((data) => data.credential || data.hash, {
    message: "Either credential or hash must be provided",
  });

revocation.post("/credentials/revoke", async (c) => {
  const body = await parseJsonBody(c);
  // SECURITY: defense-in-depth — no route accepts key material. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = revokeSchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) {
    return c.json({ error: { code: "DEDI_NOT_CONFIGURED", message: "DeDi not configured" } }, 503);
  }

  const hash = parsed.hash ?? resolveRevocationHash(parsed.credential!);

  try {
    // Fast path: try to publish synchronously. On a non-congested namespace (or
    // an already-stranded draft) this completes in well under the 10s ceiling
    // and returns 200, preserving the synchronous revoke contract.
    const result = await dediClient.publishRevocationHash(hash, parsed.namespace, parsed.reason);
    revocationsPublishedTotal.inc();
    const revokedAt = result.revoked ? result.revokedAt : new Date().toISOString();
    const responseReason = result.revoked ? result.reason : undefined;
    return c.json({
      hash,
      revoked: true,
      revokedAt,
      ...(responseReason !== undefined ? { reason: responseReason } : {}),
    });
  } catch (err) {
    // DeDi's write anchors to CORD, and BOTH steps (save-record-as-draft,
    // publish-records) can exceed the hard 10s ceiling, so a synchronous publish
    // 504s under load (opencred-releases#11). The write is eventually consistent
    // (a step that times out client-side still lands on CORD), so instead of
    // failing we ACCEPT the revoke (202) and drive the idempotent, self-healing
    // publish in the background until the record is LIVE. The client confirms
    // with POST /v1/credentials/revocation-status (#718). Any non-timeout error
    // (e.g. DeDiRecordExistsError → 409) propagates unchanged.
    if (err instanceof DeDiClientError && err.statusCode === 504) {
      void driveRevocationToLive(dediClient, hash, parsed.namespace, parsed.reason, getLogger());
      revocationsPublishedTotal.inc();
      return c.json(
        {
          hash,
          revoked: false,
          status: "pending",
          message:
            "Revocation accepted and is being published to DeDi (the CORD write exceeded the " +
            "synchronous timeout). The credential becomes revoked once the write settles; confirm " +
            "with POST /v1/credentials/revocation-status.",
        },
        202,
      );
    }
    throw err;
  }
});

// --- Revocation query endpoint (checks DeDi) ---

const querySchema = z.object({
  hash: z
    .string()
    .length(64)
    .regex(/^[a-f0-9]+$/),
  namespace: z.string().optional(),
});

revocation.post("/credentials/revocation-status", async (c) => {
  const body = await parseJsonBody(c);
  rejectKeyMaterial(body);
  const parsed = querySchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) {
    return c.json({ error: { code: "DEDI_NOT_CONFIGURED", message: "DeDi not configured" } }, 503);
  }

  const record = await dediClient.queryRevocationHash(parsed.hash, parsed.namespace);
  // Adapter's `RevocationHashRecord` no longer carries the hash (it
  // dropped out of DeDi's canonical revoke shape — record existence ⇒
  // revoked, no need to echo the key inside details). Re-attach `hash`
  // here so clients of this endpoint still get the input they queried
  // for in the response.
  return c.json({ hash: parsed.hash, ...record });
});

export { revocation };
