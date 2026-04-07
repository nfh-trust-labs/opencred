/**
 * OpenCred Server — headless HTTP API for credential issuance.
 *
 * This is the main entry point. It wires together configuration, logging,
 * authentication, error handling, and all route modules, then starts the
 * Hono HTTP server.
 *
 * SECURITY INVARIANTS:
 *  - Signing keys are loaded from local files at startup — never from requests.
 *  - Key material is NEVER logged.
 *  - JSON-LD contexts are bundled — never fetched at runtime.
 *  - Error responses are sanitized via the OpenCredError hierarchy.
 */

import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { ZodError } from "zod";

import { loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { authMiddleware } from "./middleware/auth.js";
import { errorHandler } from "./middleware/error-handler.js";
import { loadSigningKey, setActiveSigner } from "./signing/key-manager.js";
import { createSignerFromConfig } from "./signing/cloud-hsm/factory.js";
import { health } from "./routes/health.js";
import { schemas } from "./routes/schemas.js";
import { credentials } from "./routes/credentials.js";
import { batch } from "./routes/batch.js";
import { revocation } from "./routes/revocation.js";
import { packaging } from "./routes/packaging.js";
import { keys } from "./routes/keys.js";

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const config = loadConfig();
const logger = createLogger();

logger.info({ port: config.OPENCRED_PORT }, "Starting OpenCred Server");

// Load signing key.
//
// SECURITY: The signing key is loaded ONLY from the local filesystem (or
// Cloud HSM provider) at startup. The HTTP API never accepts private key
// material in any request. Only the key id, fingerprint, and algorithm are
// ever exposed — never the private key bytes.
//
// Resolution order:
//   1. Cloud HSM provider (if OPENCRED_KMS_PROVIDER is set)
//   2. Software key file (if OPENCRED_KEY_PATH is set)
//   3. None — signing endpoints will return 503
const cloudSigner = await createSignerFromConfig();
if (cloudSigner) {
  setActiveSigner(cloudSigner);
} else {
  loadSigningKey();
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = new Hono();

// Global middleware
app.use("*", authMiddleware);

// Mount routes.
//
// We expose every route under both "/" (legacy / desktop-compatible) and
// "/v1" (the versioned API surface documented in the README). New consumers
// should target the /v1 prefix; the unprefixed routes are kept for the
// existing desktop main process and tests.
app.route("/", health);
app.route("/", schemas);
app.route("/", credentials);
app.route("/", batch);
app.route("/", revocation);
app.route("/", packaging);
app.route("/", keys);

app.route("/v1", health);
app.route("/v1", schemas);
app.route("/v1", credentials);
app.route("/v1", batch);
app.route("/v1", revocation);
app.route("/v1", packaging);
app.route("/v1", keys);

// Global error handler
app.onError((err, c) => {
  // Handle Zod validation errors
  if (err instanceof ZodError) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "Request validation failed",
          details: err.errors.map((e) => ({
            path: e.path.join("."),
            message: e.message,
          })),
        },
      },
      400,
    );
  }

  return errorHandler(err, c);
});

// 404 handler
app.notFound((c) => {
  return c.json({ error: { code: "NOT_FOUND", message: "Endpoint not found" } }, 404);
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

const server = serve({
  fetch: app.fetch,
  port: config.OPENCRED_PORT,
});

logger.info({ port: config.OPENCRED_PORT }, "OpenCred Server listening");

// Graceful shutdown
function shutdown(signal: string) {
  logger.info({ signal }, "Shutting down");
  server.close(() => {
    logger.info("Server closed");
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

export { app };
