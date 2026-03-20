/**
 * Health check endpoint.
 */

import { Hono } from "hono";
import { getActiveSigner } from "../signing/key-manager.js";

const health = new Hono();

health.get("/health", (c) => {
  const signer = getActiveSigner();
  return c.json({
    status: "ok",
    signingKeyLoaded: signer !== null,
    timestamp: new Date().toISOString(),
  });
});

export { health };
