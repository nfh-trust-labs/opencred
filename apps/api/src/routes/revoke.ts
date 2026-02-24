import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { computeRevocationHash } from "@opencred/crypto";
import type { DeDiClient } from "@opencred/dedi-client";
import { ValidationError } from "@opencred/shared";

const revokeBodySchema = z
  .object({
    credentialHash: z
      .string()
      .regex(/^[a-f0-9]{64}$/, "Must be a lowercase hex SHA-256 hash")
      .optional(),
    credential: z.record(z.unknown()).optional(),
  })
  .refine((data) => data.credentialHash != null || data.credential != null, {
    message: "Either credentialHash or credential must be provided",
  });

export function createRevokeRoute(dediClient: DeDiClient) {
  const route = new Hono();

  route.post(
    "/credentials/revoke",
    zValidator("json", revokeBodySchema, (result) => {
      if (!result.success) {
        const messages = result.error.issues.map((i) => i.message).join("; ");
        throw new ValidationError(messages);
      }
    }),
    async (c) => {
      const body = c.req.valid("json");

      let hash: string;
      if (body.credentialHash) {
        hash = body.credentialHash;
      } else {
        hash = computeRevocationHash(body.credential);
      }

      await dediClient.publishRevocationHash(hash);

      return c.json({ hash, status: "revoked" }, 200);
    },
  );

  return route;
}
