/**
 * Health check endpoint.
 *
 * Returns both a liveness status and a readiness status:
 *  - Liveness: always "ok" if the process is running.
 *  - Readiness: true when the signing key is loaded (minimum requirement
 *    for the server to issue credentials).
 *
 * HTTP status codes:
 *  - 200: Ready — signing key loaded, server can issue credentials.
 *  - 503: Not ready — signing key not loaded.
 */

import { Hono } from "hono";
import { getActiveSigner } from "../signing/key-manager.js";

const health = new Hono();

health.get("/health", (c) => {
  const signer = getActiveSigner();
  const signingKeyLoaded = signer !== null;

  const body = {
    status: "ok",
    ready: signingKeyLoaded,
    signingKeyLoaded,
    timestamp: new Date().toISOString(),
  };

  return c.json(body, signingKeyLoaded ? 200 : 503);
});

export { health };
