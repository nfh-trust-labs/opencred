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

const revocation = new Hono();

const singleHashSchema = z.object({
  credential: z.record(z.unknown()),
});

const batchHashSchema = z.object({
  credentials: z.array(z.record(z.unknown())),
});

revocation.post("/credentials/revocation-hash", async (c) => {
  const body = await c.req.json();
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
  const body = await c.req.json();
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
  })
  .refine((data) => data.credential || data.hash, {
    message: "Either credential or hash must be provided",
  });

revocation.post("/credentials/revoke", async (c) => {
  const body = await c.req.json();
  // SECURITY: defense-in-depth — no route accepts key material. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = revokeSchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) {
    return c.json({ error: { code: "DEDI_NOT_CONFIGURED", message: "DeDi not configured" } }, 503);
  }

  const hash = parsed.hash ?? resolveRevocationHash(parsed.credential!);
  const result = await dediClient.publishRevocationHash(hash, parsed.namespace);

  revocationsPublishedTotal.inc();

  // publishRevocationHash always returns a revoked=true record.
  const revokedAt = result.revoked ? result.revokedAt : new Date().toISOString();
  return c.json({ hash, revoked: true, revokedAt });
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
  const body = await c.req.json();
  rejectKeyMaterial(body);
  const parsed = querySchema.parse(body);

  const dediClient = getDeDiClient();
  if (!dediClient) {
    return c.json({ error: { code: "DEDI_NOT_CONFIGURED", message: "DeDi not configured" } }, 503);
  }

  const record = await dediClient.queryRevocationHash(parsed.hash, parsed.namespace);
  return c.json(record);
});

export { revocation };
