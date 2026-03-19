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

const revocation = new Hono();

const singleHashSchema = z.object({
  credential: z.record(z.unknown()),
});

const batchHashSchema = z.object({
  credentials: z.array(z.record(z.unknown())),
});

revocation.post("/credentials/revocation-hash", async (c) => {
  const body = await c.req.json();
  const parsed = singleHashSchema.parse(body);
  const hash = computeRevocationHash(parsed.credential);
  return c.json({ hash });
});

revocation.post("/credentials/revocation-hash/batch", async (c) => {
  const body = await c.req.json();
  const parsed = batchHashSchema.parse(body);

  const hashes = parsed.credentials.map((credential, index) => ({
    index,
    hash: computeRevocationHash(credential),
  }));

  return c.json({ hashes });
});

export { revocation };
