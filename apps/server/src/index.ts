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
import { getActiveSigner, loadSigningKey, setActiveSigner } from "./signing/key-manager.js";
import { encodeDidWeb, verifyDidWeb } from "@opencred/did";
import { runAutoPublishIfEnabled } from "./auto-publish.js";
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
import { setDidAutoPublishedAtStartup } from "./startup-state.js";
import { health } from "./routes/health.js";
import { schemas } from "./routes/schemas.js";
import { credentials } from "./routes/credentials.js";
import { batch, finalizeAllRunningJobs, setBatchQueue, setJobStore } from "./routes/batch.js";
import { createJobStore } from "./batch/job-store/factory.js";
import { buildQueues, type BatchQueue, type WebhookQueue } from "./batch/queue.js";
import { revocation } from "./routes/revocation.js";
import { packaging } from "./routes/packaging.js";
import { keys } from "./routes/keys.js";
import { dedi } from "./routes/dedi.js";
import { metrics } from "./routes/metrics.js";
import { initTracing } from "./tracing.js";
import { metricsMiddleware } from "./middleware/metrics.js";
import { tracingMiddleware } from "./middleware/tracing.js";
import { wrapSignerWithTracing, type SignerKind } from "./observability/signer-span.js";
import { wrapDeDiClientWithTracing } from "./observability/dedi-span.js";
import {
  applyRateLimits,
  checkRateLimitIpExtraction,
  mountRateLimitSelfCheckRoute,
} from "./middleware/rate-limit.js";
import { readOnlyMiddleware } from "./middleware/read-only.js";

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

// Tracing (Tier 3 #10 of nfh-trust-labs/opencred#446).
//
// Opt-in via `OPENCRED_OTEL_ENABLED=true`. Default is OFF for back-compat.
// When enabled, a NodeTracerProvider is registered globally; standard
// OTel env vars apply (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME,
// OTEL_TRACES_SAMPLER, OTEL_TRACES_SAMPLER_ARG).
//
// The critical-path span surface is:
//   - HTTP server spans (via `tracingMiddleware`)
//   - `signer.sign` spans (via `wrapSignerWithTracing` below)
//   - `dedi.lookup_record` / `publish_record` / `update_record`
//     (via `wrapDeDiClientWithTracing`)
//   - `batch.run` + per-row `batch.row.process`
//     (via the batch engines themselves; they reach for the tracer
//     directly and no-op when tracing is off)
//   - `verify.credential` / `verify.did_resolve` / `verify.schema_validate`
//     (in the credentials route)
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
// Cloud HSM provider determines the signer kind for OTel attributes.
// `Signer.type` is "software" for every cloud HSM signer (since the
// signature shape is identical to a software EC sign), so we tag the
// span kind explicitly based on the configured provider — operators
// looking at `signer.sign` durations in Grafana need to be able to
// tell AWS KMS apart from a local PEM file.
const cloudSigner = await createSignerFromConfig();
if (cloudSigner) {
  const kmsKind: SignerKind =
    config.OPENCRED_KMS_PROVIDER === "aws"
      ? "cloud-hsm-aws"
      : config.OPENCRED_KMS_PROVIDER === "azure"
        ? "cloud-hsm-azure"
        : config.OPENCRED_KMS_PROVIDER === "gcp"
          ? "cloud-hsm-gcp"
          : "software";
  setActiveSigner(wrapSignerWithTracing(cloudSigner, kmsKind));
} else {
  const loaded = loadSigningKey();
  if (loaded) {
    // Re-wrap the loaded software signer. `loadSigningKey` calls
    // `setActiveSigner` internally, so we replace the singleton with
    // the tracing-instrumented version here. Kind is derived from
    // `Signer.type` so OS-cert / PKCS#11 / software paths show
    // distinct breakdowns in dashboards.
    const kind: SignerKind =
      loaded.type === "pkcs11" ? "pkcs11" : loaded.type === "os-cert" ? "os-cert" : "software";
    setActiveSigner(wrapSignerWithTracing(loaded, kind));
  }
}

// ---------------------------------------------------------------------------
// Issuer identity validation
// ---------------------------------------------------------------------------
// Reconcile the configured DID method with the loaded signer before serving
// any request. This catches the "config drift" failure mode where someone
// edits env vars and silently changes which issuer identity the server
// signs under. The check is fail-closed: a misconfiguration here exits the
// process rather than starting up under an ambiguous identity.
//
// What we validate today:
//   - method=key: signer.id must be a did:key (its `id` is the VM ref, e.g.
//     `did:key:z…#z…`). did:jwk-backed signers (RSA keys) are rejected.
//   - method=web: domain must be set (already enforced in config), and the
//     `did.json` at that domain must be reachable. We log the configured
//     did:web and warn (don't fail) if `.well-known` validation reports it
//     unreachable — the operator may legitimately bring up the server before
//     the DNS / web host is live.
//
// What we do NOT validate yet (follow-up):
//   - That the public key bytes published at did:web match the loaded
//     signer's key. This requires extending the Signer interface to expose
//     publicKeyJwk; tracked separately. For now operators can run
//     `opencred identity show` to print the configured DID + key fingerprint
//     and reconcile manually.
{
  const activeSigner = getActiveSigner();
  if (!activeSigner) {
    // No signer loaded — signing endpoints already return 503; nothing
    // to reconcile. The earlier "No OPENCRED_KEY_PATH configured" log
    // covers the operator-visible case.
    logger.info(
      { didMethod: config.OPENCRED_ISSUER_DID_METHOD },
      "No active signer; skipping issuer-identity validation",
    );
  } else if (config.OPENCRED_ISSUER_DID_METHOD === "key") {
    if (!activeSigner.id.startsWith("did:key:")) {
      const msg =
        `OPENCRED_ISSUER_DID_METHOD=key but the loaded signer (${activeSigner.id}) ` +
        "is not a did:key. Software signers using RSA produce did:jwk; either " +
        "switch to an EC key (P-256/P-384/Ed25519) or set " +
        "OPENCRED_ISSUER_DID_METHOD=web with OPENCRED_ISSUER_DOMAIN.";
      logger.fatal(msg);
      process.stderr.write(`\n[opencred-server] FATAL: ${msg}\n\n`);
      process.exit(1);
    }
    const issuerDid = activeSigner.id.split("#")[0];
    logger.info({ issuerDid, didMethod: "key" }, "Issuer identity configured");
  } else {
    // method === "web"
    const issuerDid = encodeDidWeb(config.OPENCRED_ISSUER_DOMAIN!);
    // Skip the plain-HTTPS reachability probe when DeDi will host the DID
    // document OR when the operator opted into startup auto-publish — in
    // both cases the document is published a few steps later (after the
    // DeDi client init / ensureRegistries call), so a "not reachable" warn
    // here would contradict the success log emitted seconds later.
    const willPublishToDeDi = config.OPENCRED_DEDI_HOST_DID_DOC || config.OPENCRED_AUTO_PUBLISH_KEY;
    if (willPublishToDeDi) {
      logger.info(
        { issuerDid, didMethod: "web" },
        "did:web will be published via DeDi at startup; boot reachability probe skipped — " +
          "DID document will be published after DeDi client init",
      );
    } else {
      const result = await verifyDidWeb(issuerDid).catch((err: unknown) => ({
        accessible: false,
        error: err instanceof Error ? err.message : "did:web verification crashed",
      }));
      if (!result.accessible) {
        logger.warn(
          { issuerDid, error: result.error },
          "did:web DID document not currently reachable — the server will still start, " +
            "but verifiers cannot resolve this issuer until the document is published",
        );
      }
      logger.info(
        { issuerDid, didMethod: "web", accessible: result.accessible },
        "Issuer identity configured",
      );
    }
  }
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

const dediClientRaw = createDeDiClientFromConfig(config, logger);
const dediClient = dediClientRaw
  ? wrapDeDiClientWithTracing(dediClientRaw, config.OPENCRED_DEDI_BASE_URL!)
  : null;
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

  // Auto-publish issuer DID at startup (opt-in via OPENCRED_AUTO_PUBLISH_KEY
  // or OPENCRED_DEDI_HOST_DID_DOC=true + did:web). Helper is non-throwing
  // and returns a structured outcome we surface via /v1/health.
  const autoPublishResult = await runAutoPublishIfEnabled(
    config,
    dediClient,
    getActiveSigner(),
    logger,
  );
  setDidAutoPublishedAtStartup(autoPublishResult.didPublish);
} else {
  logger.info("DeDi not configured — revocation checks disabled");
  setDidAutoPublishedAtStartup(false);
}

// ---------------------------------------------------------------------------
// JobStore (batch jobs)
// ---------------------------------------------------------------------------
// Tier 2 #5 of nfh-trust-labs/opencred#446: replace the in-process Map
// with a pluggable backing store. Default is `memory` (no change for
// existing single-instance deployments); `redis` unlocks horizontal
// scale across replicas.
//
// SECURITY: `createJobStore` logs only host/port for Redis. The full URL
// — which may carry credentials — never appears in logs.

const jobStore = await createJobStore(config, logger);
setJobStore(jobStore);

// ---------------------------------------------------------------------------
// BullMQ batch dispatch (Tier 3 #8 of nfh-trust-labs/opencred#446)
// ---------------------------------------------------------------------------
// When OPENCRED_BATCH_DISPATCH=queue the API process enqueues a BatchJob
// onto Redis and returns 202 immediately. The actual signing happens
// inside a separate worker process (apps/server/src/worker.ts).
//
// In `inline` mode (default) the queue handle stays unset and the route
// runs the engine in-band — bit-identical to every release before this.
//
// SECURITY: the queue payload NEVER carries key material. Workers load
// their own signing key from the same OPENCRED_KEY_PATH / Cloud HSM
// configuration as the API process — see worker.ts.

let queues: { batch: BatchQueue; webhook: WebhookQueue } | null = null;
if (config.OPENCRED_BATCH_DISPATCH === "queue") {
  queues = await buildQueues(config, logger);
  setBatchQueue(queues.batch);
} else {
  logger.info({ dispatch: "inline" }, "Batch dispatch: in-process (no queue)");
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
//
// Tracing middleware runs FIRST so HTTP spans are the outermost scope —
// every downstream call (signer, batch, dedi) nests under the request
// span. The middleware is cheap (single function call) when tracing is
// disabled; we still apply it unconditionally so a future
// `OPENCRED_OTEL_ENABLED=true` flip doesn't require a redeploy of the
// middleware chain.
app.use("*", tracingMiddleware);

app.use("*", metricsMiddleware);

// Per-route rate limiting (issue #446 Tier 1).
//
// Mounted BEFORE auth so unauthenticated traffic burns budget too — a
// hostile peer hammering /credentials/issue with bogus tokens should hit
// the 429 path before we ever spend a syscall on the bearer check, and a
// bug in the auth path shouldn't accidentally make the surface
// unlimited. The rate limiter middleware short-circuits cleanly when
// OPENCRED_RATE_LIMIT_ENABLED=false.
applyRateLimits(app);

// Mount the rate-limit self-check route used by the boot-time probe
// (see below). It returns the bucket key the limiter would have used
// for the request — used to confirm we extract a real IP from this
// runtime's adapter rather than collapsing every anonymous client into
// `ip:unknown`. Registered BEFORE auth so the probe doesn't need a key.
mountRateLimitSelfCheckRoute(app);

app.use("*", authMiddleware);

// Read-only mode enforcement (Tier 3 #9 of nfh-trust-labs/opencred#446).
//
// Mounted AFTER auth so callers still need a valid Bearer token to reach the
// read surface — read-only is a deployment topology, not an authentication
// bypass. The middleware is a no-op when `OPENCRED_READ_ONLY=false`
// (default).
app.use("*", readOnlyMiddleware);

// Log read-only mode loudly at startup so an operator who flipped the flag
// in a write-tier env var by accident sees it on boot rather than after a
// confused integrator hits a 405 in prod.
if (config.OPENCRED_READ_ONLY) {
  logger.warn(
    "OPENCRED_READ_ONLY=true — write endpoints (issue, batch, revoke, keys/publish) " +
      "will return 405. This server is a read tier; send write traffic elsewhere.",
  );
}

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
app.route("/", dedi);

app.route("/v1", health);
app.route("/v1", metrics);
app.route("/v1", schemas);
app.route("/v1", credentials);
app.route("/v1", batch);
app.route("/v1", revocation);
app.route("/v1", packaging);
app.route("/v1", keys);
app.route("/v1", dedi);

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

// ---------------------------------------------------------------------------
// Rate-limit IP-extraction self-check
// ---------------------------------------------------------------------------
// Catches the failure mode where the Hono context's `c.env.incoming.socket`
// shape isn't present in the current runtime — that path is the only way
// the limiter can derive a per-IP bucket for unauthenticated requests, so
// if it returns `ip:unknown` here every anonymous client collapses into a
// single global bucket. We log this loudly at startup so an operator who
// boots the server in an unexpected environment (a non-Node adapter, a
// proxy that strips peer info) gets a warning they can grep for, rather
// than discovering the misconfiguration only when a real DoS arrives.
//
// We only run the probe when the limiter itself is enabled — if rate
// limiting is off, the bucket key is irrelevant. We run it asynchronously
// so the probe never blocks request handling, and we never fail the
// process on a probe error: an over-zealous fail-closed here would
// prevent a perfectly functional server from booting just because its
// loopback fetch failed for unrelated reasons.
if (config.OPENCRED_RATE_LIMIT_ENABLED) {
  void (async () => {
    // Wait for `server.listening`. `@hono/node-server` exposes `listening`
    // and emits "listening" — both are reliable on Node, but `serve()`
    // may have already finished by the time we get here, so we test the
    // current state first.
    if (!server.listening) {
      await new Promise<void>((resolve) => server.once("listening", () => resolve()));
    }
    const addr = server.address();
    let port: number | undefined;
    if (addr && typeof addr === "object") {
      port = addr.port;
    }
    if (port === undefined) {
      logger.warn("Rate-limit self-check skipped: server.address() did not return a numeric port");
      return;
    }
    const probeUrl = `http://127.0.0.1:${port}`;
    const result = await checkRateLimitIpExtraction(probeUrl);
    if (result.ok) {
      logger.info(
        { bucket: result.key },
        "Rate-limit IP extraction OK — remote address detected on the runtime adapter",
      );
    } else {
      logger.warn(
        { error: result.error, bucket: result.key },
        "Rate-limit IP extraction returned ip:unknown — every anonymous client will share " +
          "ONE bucket. Set OPENCRED_TRUST_PROXY=true if your runtime sits behind a trusted " +
          "L7 proxy, or check that @hono/node-server is the active adapter.",
      );
    }
  })().catch((err: unknown) => {
    // Defensive — `checkRateLimitIpExtraction` already swallows its
    // errors and returns `ok: false`. This catch only fires if the IIFE
    // itself throws (e.g. `server.address()` semantics changed). Logged
    // and dropped — the server keeps running.
    logger.warn(
      { error: err instanceof Error ? err.message : String(err) },
      "Rate-limit self-check crashed",
    );
  });
}

// Batch-job purge:
//
//  - MemoryJobStore runs its own internal purge sweep (see `MemoryJobStore`
//    constructor) — no module-level timer needed here anymore.
//  - RedisJobStore relies on Redis-managed TTL (`SET ... EX`) — same.
//
// This replaces the old `startBatchJobCleanup` loop. Both stores honour
// the `OPENCRED_SESSION_TTL` invariant from CLAUDE.md rule 3.

// TODO(#109): When a DeDi client is available in the server, add optional
// startup behaviour: if OPENCRED_DEDI_PUBLISH_BUNDLED=true, iterate through
// the schema registry and publish each schema to DeDi via
// DeDiClient.publishSchema(). Errors should be logged, not thrown.

// Graceful shutdown
//
// When SIGTERM/SIGINT lands:
//  1. Mark every in-flight batch on THIS replica as "interrupted" in the
//     JobStore. A replica picking up the work later (or an operator
//     reviewing the run) can distinguish "the host died mid-batch" from
//     "the job failed".
//  2. Close the HTTP server (drains in-flight requests).
//  3. Close the JobStore (flush Redis socket / clear in-memory timer).
//  4. Shut down the OTel tracer.
function shutdown(signal: string) {
  logger.info({ signal }, "Shutting down");
  void (async () => {
    try {
      const interrupted = await finalizeAllRunningJobs();
      if (interrupted > 0) {
        logger.info({ count: interrupted }, "Finalized in-flight batch jobs as 'interrupted'");
      }
    } catch (err) {
      logger.warn({ err }, "Failed to finalize in-flight batch jobs during shutdown");
    }
    server.close(async () => {
      try {
        await jobStore.close();
      } catch (err) {
        logger.warn({ err }, "Failed to close JobStore");
      }
      if (queues) {
        try {
          await queues.batch.close();
          await queues.webhook.close();
        } catch (err) {
          logger.warn({ err }, "Failed to close BullMQ queues");
        }
      }
      if (tracer) await tracer.shutdown();
      logger.info("Server closed");
      process.exit(0);
    });
  })();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

export { app };
