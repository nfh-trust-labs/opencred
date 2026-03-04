import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { computeRevocationHash } from "@opencred/crypto";
import { ValidationError } from "@opencred/shared";

const singleHashSchema = z.object({
  credential: z.record(z.unknown()).refine((v) => Object.keys(v).length > 0, {
    message: "credential must not be empty",
  }),
});

const batchHashSchema = z.object({
  credentials: z
    .array(
      z.record(z.unknown()).refine((v) => Object.keys(v).length > 0, {
        message: "Each credential must not be empty",
      }),
    )
    .min(1, "At least one credential is required"),
});

export function createRevocationHashRoute() {
  const route = new Hono();

  route.post(
    "/",
    zValidator("json", singleHashSchema, (result) => {
      if (!result.success) {
        const messages = result.error.issues.map((i) => i.message).join("; ");
        throw new ValidationError(messages);
      }
    }),
    async (c) => {
      const body = c.req.valid("json");
      const hash = computeRevocationHash(body.credential);
      return c.json({ hash }, 200);
    },
  );

  route.post(
    "/batch",
    zValidator("json", batchHashSchema, (result) => {
      if (!result.success) {
        const messages = result.error.issues.map((i) => i.message).join("; ");
        throw new ValidationError(messages);
      }
    }),
    async (c) => {
      const body = c.req.valid("json");
      const hashes = body.credentials.map((credential, index) => ({
        hash: computeRevocationHash(credential),
        index,
      }));
      return c.json({ hashes }, 200);
    },
  );

  return route;
}
