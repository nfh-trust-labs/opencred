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
import { bodyLimit } from "hono/body-limit";
import { serve } from "@hono/node-server";
import { ZodError } from "zod";

import { ConfigError, loadConfig, type ServerConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { authMiddleware } from "./middleware/auth.js";
import { errorHandler } from "./middleware/error-handler.js";
import { loadSigningKey, setActiveSigner } from "./signing/key-manager.js";
import { createSignerFromConfig } from "./signing/cloud-hsm/factory.js";
import { homedir } from "node:os";
import { join } from "node:path";
import { createRegistryWithUpdates, Validator } from "@opencred/schema-engine";
import { CscaTrustStore } from "@opencred/verification";
import { setTrustStore } from "./trust-store.js";
import { setSchemaRegistry } from "./schema-registry-singleton.js";
import { setValidator } from "./validator-singleton.js";
import { createDeDiClientFromConfig } from "./dedi-factory.js";
import { setDeDiClient } from "./dedi-singleton.js";
import { health } from "./routes/health.js";
import { schemas } from "./routes/schemas.js";
import { credentials } from "./routes/credentials.js";
import { batch, startBatchJobCleanup } from "./routes/batch.js";
import { revocation } from "./routes/revocation.js";
import { packaging } from "./routes/packaging.js";
import { keys } from "./routes/keys.js";
import { metrics } from "./routes/metrics.js";
import { initTracing } from "./tracing.js";
import { metricsMiddleware } from "./middleware/metrics.js";

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

let config: ServerConfig;
try {
  config = loadConfig();
} catch (err) {
  // Config errors at startup must be surfaced to stderr in a human-readable
  // form. The logger is not yet initialised at this point — write directly
  // to process.stderr so the operator sees the failure regardless of
  // OPENCRED_LOG_LEVEL.
  if (err instanceof ConfigError) {
    process.stderr.write(`\n[opencred-server] FATAL: ${err.message}\n\n`);
  } else if (err instanceof Error) {
    process.stderr.write(`\n[opencred-server] FATAL: ${err.message}\n\n`);
  } else {
    process.stderr.write(`\n[opencred-server] FATAL: failed to load configuration\n\n`);
  }
  process.exit(1);
}

const logger = createLogger();

if (config.OPENCRED_DEV_MODE_NO_AUTH) {
  // Loud, multi-line warning so the operator cannot miss this in normal logs.
  const banner = "*".repeat(78);
  logger.warn(banner);
  logger.warn(
    "WARNING: authentication disabled (OPENCRED_DEV_MODE_NO_AUTH=true). " +
      "DO NOT use in production.",
  );
  logger.warn(
    "All protected endpoints (POST /credentials/issue, POST /credentials/verify, " +
      "POST /batch, POST /revocation, GET /v1/keys, etc.) are reachable without an API key.",
  );
  logger.warn(
    "Set OPENCRED_API_KEY and unset OPENCRED_DEV_MODE_NO_AUTH before exposing this server to any network you do not fully control.",
  );
  logger.warn(banner);
}

// Tracing (opt-in via OTEL_EXPORTER_OTLP_ENDPOINT)
const tracer = initTracing();
if (tracer) {
  logger.info("OpenTelemetry tracing enabled");
}

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
// Schema Registry (with optional remote updates)
// ---------------------------------------------------------------------------
// The registry is initialised ONCE at startup. If OPENCRED_SCHEMA_UPDATE_URL
// is configured, newer schemas are fetched from the manifest, verified, and
// merged into the bundled set. On any failure the bundled schemas are used.

const schemaRegistry = await createRegistryWithUpdates({
  manifestUrl: config.OPENCRED_SCHEMA_UPDATE_URL,
  cacheDir: config.OPENCRED_SCHEMA_CACHE_DIR ?? join(homedir(), ".opencred", "schemas"),
  timeoutMs: 10_000,
  logger,
});
setSchemaRegistry(schemaRegistry);
setValidator(new Validator(schemaRegistry));
logger.info({ count: schemaRegistry.listSchemas().length }, "Schema registry initialised");

// ---------------------------------------------------------------------------
// CSCA Trust Store
// ---------------------------------------------------------------------------
// Load the CSCA trust store once at startup. The trust store is shared across
// all verification requests via the `getTrustStore()` singleton.

if (config.OPENCRED_CSCA_TRUST_STORE_PATH) {
  const trustStore = await CscaTrustStore.fromDirectory(config.OPENCRED_CSCA_TRUST_STORE_PATH, {
    onWarning: (msg) => logger.warn(msg),
  });
  setTrustStore(trustStore);
  logger.info(
    { path: config.OPENCRED_CSCA_TRUST_STORE_PATH, size: trustStore.size },
    "CSCA trust store loaded",
  );
  if (trustStore.size === 0) {
    logger.warn(
      "CSCA trust store is empty — DSC-backed credentials will fail X.509 chain validation",
    );
  }
} else {
  logger.warn(
    "OPENCRED_CSCA_TRUST_STORE_PATH is not set — DSC-backed credentials will fail X.509 chain validation",
  );
}

// ---------------------------------------------------------------------------
// DeDi Client (optional)
// ---------------------------------------------------------------------------
// Initialise the DeDi client once at startup from OPENCRED_DEDI_* env vars.
// When unconfigured, the server functions without DeDi — revocation checks
// are skipped during verification.

const dediClient = createDeDiClientFromConfig(config, logger);
if (dediClient) {
  setDeDiClient(dediClient);
  await dediClient.ensureRegistries(config.OPENCRED_DEDI_NAMESPACE!).catch((err: unknown) => {
    logger.warn(
      { error: err instanceof Error ? err.message : String(err) },
      "DeDi registry bootstrap failed — continuing without registry pre-creation",
    );
  });
  logger.info(
    { baseUrl: config.OPENCRED_DEDI_BASE_URL, namespace: config.OPENCRED_DEDI_NAMESPACE },
    "DeDi client initialized",
  );
} else {
  logger.info("DeDi not configured — revocation checks disabled");
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = new Hono();

// ---------------------------------------------------------------------------
// Body size limits (MED-02)
// ---------------------------------------------------------------------------
//
// Applied before auth and metrics so oversize requests are rejected
// immediately with a 413 before any auth check, DB lookup, or signer lookup
// runs. Two distinct caps:
//
//   - `OPENCRED_MAX_BATCH_BODY_BYTES` for `POST /credentials/batch` and its
//     `/v1/...` twin — batch CSV uploads are legitimately large.
//   - `OPENCRED_MAX_BODY_BYTES` for every other route (default 50 MiB).
//
// `hono/body-limit` takes a single `maxSize`, so we register two middleware
// instances in sequence: the batch path gets the larger cap; the wildcard
// follows with the tighter cap but skips the batch path via its own scope
// (batch path already passed the batch-scoped check first, and we skip the
// second middleware explicitly to avoid false rejects).
const BATCH_PATHS = new Set(["/credentials/batch", "/v1/credentials/batch"]);

app.use(
  "/credentials/batch",
  bodyLimit({
    maxSize: config.OPENCRED_MAX_BATCH_BODY_BYTES,
    onError: (c) =>
      c.json({ error: { code: "PAYLOAD_TOO_LARGE", message: "Request body exceeds limit" } }, 413),
  }),
);
app.use(
  "/v1/credentials/batch",
  bodyLimit({
    maxSize: config.OPENCRED_MAX_BATCH_BODY_BYTES,
    onError: (c) =>
      c.json({ error: { code: "PAYLOAD_TOO_LARGE", message: "Request body exceeds limit" } }, 413),
  }),
);

// General cap applied to all non-batch routes. Skipped on batch paths so
// the tighter non-batch limit isn't wrongly enforced against CSV uploads.
app.use("*", async (c, next) => {
  if (BATCH_PATHS.has(c.req.path)) return next();
  return bodyLimit({
    maxSize: config.OPENCRED_MAX_BODY_BYTES,
    onError: (ctx) =>
      ctx.json(
        { error: { code: "PAYLOAD_TOO_LARGE", message: "Request body exceeds limit" } },
        413,
      ),
  })(c, next);
});

// Global middleware
app.use("*", metricsMiddleware);
app.use("*", authMiddleware);

// Mount routes.
//
// We expose every route under both "/" (legacy / desktop-compatible) and
// "/v1" (the versioned API surface documented in the README). New consumers
// should target the /v1 prefix; the unprefixed routes are kept for the
// existing desktop main process and tests.
app.route("/", health);
app.route("/", metrics);
app.route("/", schemas);
app.route("/", credentials);
app.route("/", batch);
app.route("/", revocation);
app.route("/", packaging);
app.route("/", keys);

app.route("/v1", health);
app.route("/v1", metrics);
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

// Start the batch-job purge loop. Jobs in the in-memory Map are evicted
// once their (completedAt ?? createdAt) + OPENCRED_SESSION_TTL is in the
// past, honouring CLAUDE.md rule 3 on ephemeral session data. We hold the
// handle so shutdown (or a test tear-down) can cancel it cleanly.
const batchCleanupInterval = startBatchJobCleanup(
  5 * 60 * 1000, // sweep every 5 minutes
  config.OPENCRED_SESSION_TTL * 1000,
);

// TODO(#109): When a DeDi client is available in the server, add optional
// startup behaviour: if OPENCRED_DEDI_PUBLISH_BUNDLED=true, iterate through
// the schema registry and publish each schema to DeDi via
// DeDiClient.publishSchema(). Errors should be logged, not thrown.

// Graceful shutdown
function shutdown(signal: string) {
  logger.info({ signal }, "Shutting down");
  clearInterval(batchCleanupInterval);
  server.close(async () => {
    if (tracer) await tracer.shutdown();
    logger.info("Server closed");
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

export { app };
