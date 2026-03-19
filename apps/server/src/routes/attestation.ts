/**
 * Attestation challenge endpoints (stub).
 *
 * POST /attestation/challenge          — request an attestation challenge
 * POST /attestation/challenge/:id/verify — submit proof, get Key Attestation Credential
 *
 * These are stubs for now — full implementation requires Cloud HSM integration
 * (Phase 6/7). The endpoints exist so the API surface is complete.
 */

import { Hono } from "hono";
import { randomUUID } from "node:crypto";
import { NotImplementedError } from "@opencred/shared";

const attestation = new Hono();

// In-memory challenge store
const challenges = new Map<string, {
  id: string;
  createdAt: string;
  expiresAt: string;
  nonce: string;
}>();

attestation.post("/attestation/challenge", (c) => {
  const id = randomUUID();
  const nonce = randomUUID();
  const now = new Date();
  const expires = new Date(now.getTime() + 5 * 60 * 1000); // 5 min TTL

  challenges.set(id, {
    id,
    createdAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    nonce,
  });

  return c.json({
    challengeId: id,
    nonce,
    expiresAt: expires.toISOString(),
  });
});

attestation.post("/attestation/challenge/:id/verify", async (c) => {
  const id = c.req.param("id");
  const challenge = challenges.get(id);

  if (!challenge) {
    return c.json({ error: { code: "NOT_FOUND", message: "Challenge not found or expired" } }, 404);
  }

  if (new Date() > new Date(challenge.expiresAt)) {
    challenges.delete(id);
    return c.json({ error: { code: "EXPIRED", message: "Challenge has expired" } }, 410);
  }

  // Full implementation requires OpenCred DSC + Cloud HSM signing
  throw new NotImplementedError(
    "Attestation verification requires Cloud HSM integration (Phase 7)",
  );
});

export { attestation };
