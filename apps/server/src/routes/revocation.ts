/**
 * Revocation hash computation endpoints.
 *
 * POST /credentials/revocation-hash       — compute a single revocation hash
 * POST /credentials/revocation-hash/batch — compute batch revocation hashes
 *
 * Uses JCS canonicalization + SHA-256 from @opencred/crypto.
 */

import { Hono } from "hono";
import { z } from "zod";
import { computeRevocationHash } from "@opencred/crypto";
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
  const hash = computeRevocationHash(parsed.credential);
  return c.json({ hash });
});

revocation.post("/credentials/revocation-hash/batch", async (c) => {
  const body = await c.req.json();
  // SECURITY: defense-in-depth — no route accepts key material. See CLAUDE.md rule 1.
  rejectKeyMaterial(body);
  const parsed = batchHashSchema.parse(body);

  const hashes = parsed.credentials.map((credential, index) => ({
    index,
    hash: computeRevocationHash(credential),
  }));

  return c.json({ hashes });
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
    return c.json(
      { error: { code: "DEDI_NOT_CONFIGURED", message: "DeDi not configured" } },
      503,
    );
  }

  const hash = parsed.hash ?? computeRevocationHash(parsed.credential!);
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
    return c.json(
      { error: { code: "DEDI_NOT_CONFIGURED", message: "DeDi not configured" } },
      503,
    );
  }

  const record = await dediClient.queryRevocationHash(parsed.hash, parsed.namespace);
  return c.json(record);
});

export { revocation };
