/**
 * Server configuration — Zod schema for all environment variables.
 *
 * All configuration is loaded from environment variables at startup.
 * Sensitive values (key paths, API keys) are validated but NEVER logged.
 *
 * SECURITY: Authentication is REQUIRED by default. The server will refuse
 * to start unless OPENCRED_API_KEY is set or OPENCRED_DEV_MODE_NO_AUTH=true
 * is explicitly opted into (and only outside of NODE_ENV=production).
 */

import { z } from "zod";
import { OpenCredError } from "@opencred/shared";

/**
 * Coerce common truthy/falsy strings into a boolean. Anything else throws.
 * Recognised true:  "true", "1", "yes", "on"
 * Recognised false: "false", "0", "no", "off", "" (unset)
 */
const booleanFromString = z
  .preprocess((value) => {
    if (value === undefined || value === null || value === "") return false;
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (["true", "1", "yes", "on"].includes(normalized)) return true;
      if (["false", "0", "no", "off"].includes(normalized)) return false;
    }
    return value;
  }, z.boolean())
  .default(false);

const configSchema = z.object({
  /** Port the HTTP server listens on. */
  OPENCRED_PORT: z.coerce.number().int().min(1).max(65535).default(3100),

  /**
   * Bearer token for API authentication. REQUIRED for protected endpoints
   * unless OPENCRED_DEV_MODE_NO_AUTH=true is explicitly set.
   */
  OPENCRED_API_KEY: z.string().min(1).optional(),

  /**
   * Explicit opt-out for authentication, intended for local development only.
   * When set to true, protected endpoints are reachable without an API key.
   * The server logs a loud warning at startup and REFUSES to start if
   * NODE_ENV=production is set alongside this flag.
   *
   * SECURITY: This flag is the only way to run without an API key. There is
   * no silent fallback — if neither OPENCRED_API_KEY nor this flag is set,
   * the server refuses to start.
   */
  OPENCRED_DEV_MODE_NO_AUTH: booleanFromString,

  /** Log level for pino. */
  OPENCRED_LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),

  /** Path to the signing key file (PEM, JWK, PKCS#8, or PFX). */
  OPENCRED_KEY_PATH: z.string().optional(),

  /** Password for PFX key files. */
  OPENCRED_KEY_PASSWORD: z.string().optional(),

  /** Label for the signing key (displayed in metadata). */
  OPENCRED_KEY_LABEL: z.string().default("server-key"),

  /** Maximum rows allowed in a single batch CSV. */
  OPENCRED_BATCH_ROW_LIMIT: z.coerce.number().int().min(1).default(1000),

  /** Session TTL in seconds (for ephemeral credential data). Default: 4 hours. */
  OPENCRED_SESSION_TTL: z.coerce.number().int().min(60).default(14400),

  /**
   * Maximum request body size in bytes for all routes except batch CSV
   * ingestion (see `OPENCRED_MAX_BATCH_BODY_BYTES`). Enforced globally via
   * `hono/body-limit` middleware; oversize requests receive a 413 with a
   * stable `PAYLOAD_TOO_LARGE` error code. Default: 50 MiB.
   */
  OPENCRED_MAX_BODY_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .default(50 * 1024 * 1024),

  /**
   * Maximum request body size in bytes for `POST /credentials/batch`.
   * Batch jobs carry CSVs that can legitimately dwarf a single credential
   * payload; the default is 4x the general limit. Must be at least 1 KiB.
   * Default: 200 MiB.
   */
  OPENCRED_MAX_BATCH_BODY_BYTES: z.coerce
    .number()
    .int()
    .min(1024)
    .default(200 * 1024 * 1024),

  /**
   * Dedicated HMAC secret used to sign batch-completion webhooks.
   * Required (per LOW-04) whenever a batch is submitted with a `webhookUrl`
   * — requests that supply a webhookUrl while this is unset are rejected at
   * the route boundary with a 400. Kept distinct from `OPENCRED_API_KEY`
   * so the two can be rotated independently. Minimum 32 chars to match
   * typical HMAC-SHA256 secret strength guidance.
   */
  OPENCRED_WEBHOOK_SECRET: z.string().min(32).optional(),

  // --- Issuer identity (DID method) ---

  /**
   * Which DID method this server's issuer identity uses.
   *
   * - `key` (default): issuer DID is derived from the signer's public key
   *   as `did:key:z…`. The DID is self-contained — verifiers resolve it
   *   offline without any network call. Best when the server has no public
   *   domain, runs air-gapped, or wants offline-verifiable credentials.
   *   Note: did:key has no key rotation; treat HSM-backed keys as a
   *   compensating control.
   *
   * - `web`: issuer DID is `did:web:<OPENCRED_ISSUER_DOMAIN>`. Verifiers
   *   resolve the DID over HTTPS from that domain. Best when the issuer
   *   already operates a public web endpoint, because did:web gives you
   *   key rotation and a human-readable issuer identity.
   *
   * Default is `key` to preserve the implicit behaviour that existed
   * before this option was introduced (the software signer's `id` is
   * always a did:key VM identifier).
   */
  OPENCRED_ISSUER_DID_METHOD: z.enum(["key", "web"]).default("key"),

  /**
   * Domain for did:web. REQUIRED when `OPENCRED_ISSUER_DID_METHOD=web`.
   * The server expects a `did.json` document hosted at
   * `https://<domain>/.well-known/did.json` (or at a custom path when the
   * domain string contains colons — see did:web spec). The server does NOT
   * host the DID document itself; the operator is responsible for serving
   * it from their own web infrastructure or via DeDi-as-bundled-hosting
   * (`OPENCRED_DEDI_HOST_DID_DOC=true`).
   */
  OPENCRED_ISSUER_DOMAIN: z.string().optional(),

  /**
   * When true and DeDi is configured, the server will publish its DID
   * document to DeDi at startup. Used as bundled hosting for did:web
   * issuers who don't want to run their own web server. Ignored when
   * `OPENCRED_ISSUER_DID_METHOD=key` (did:key needs no hosted document) —
   * operators can flip methods without scrubbing this env var.
   */
  OPENCRED_DEDI_HOST_DID_DOC: booleanFromString,

  // --- Cloud HSM (KMS) configuration ---

  /** KMS provider: aws | azure | gcp | none. Default: none (file-based). */
  OPENCRED_KMS_PROVIDER: z.enum(["aws", "azure", "gcp", "none"]).default("none"),

  /** AWS KMS key ARN (required when OPENCRED_KMS_PROVIDER=aws). */
  OPENCRED_KMS_KEY_ARN: z.string().optional(),

  /** Azure Key Vault URL (required when OPENCRED_KMS_PROVIDER=azure). */
  OPENCRED_AZURE_KEY_VAULT_URL: z.string().url().optional(),

  /** Azure Key Vault key name (required when OPENCRED_KMS_PROVIDER=azure). */
  OPENCRED_AZURE_KEY_NAME: z.string().optional(),

  /** GCP KMS key resource name (required when OPENCRED_KMS_PROVIDER=gcp). */
  OPENCRED_GCP_KMS_KEY_NAME: z.string().optional(),

  /**
   * Per-call timeout for Cloud KMS sign() operations, in milliseconds.
   *
   * Without a timeout, a stuck or slow KMS endpoint blocks the batch
   * engine indefinitely (the row loop is serial and `engine.cancel()`
   * only checks between rows). Default 30 s is enough for a healthy
   * call, tight enough to surface real outages quickly.
   */
  OPENCRED_KMS_TIMEOUT_MS: z.coerce.number().int().min(1000).max(120000).default(30000),

  /**
   * Path to a directory containing PEM/DER-encoded CSCA root certificates
   * used as trust anchors when verifying credentials with embedded x5c
   * chains (required by `checkX509Chain` per nfh-trust-labs/opencred#316).
   * When unset, the verifier still functions for non-DSC credentials but
   * will fail closed for any credential that carries an x5c chain.
   *
   * At startup, the trust store is loaded once (via `CscaTrustStore.fromDirectory`)
   * and shared across all verification requests.
   */
  OPENCRED_CSCA_TRUST_STORE_PATH: z.string().optional(),

  // --- Schema update configuration ---

  /** HTTPS URL of the schema update manifest. If unset, schema updates are disabled. */
  OPENCRED_SCHEMA_UPDATE_URL: z.string().url().optional(),

  /** Local directory for caching updated schemas between restarts. */
  OPENCRED_SCHEMA_CACHE_DIR: z.string().optional(),

  // --- DeDi integration (optional) ---

  /** Base URL for the DeDi instance (e.g. https://dedi.example.com). When unset, DeDi is disabled. */
  OPENCRED_DEDI_BASE_URL: z.string().url().optional(),

  /** Authentication type for DeDi: api-key or bearer. Required when OPENCRED_DEDI_BASE_URL is set. */
  OPENCRED_DEDI_AUTH_TYPE: z.enum(["api-key", "bearer"]).optional(),

  /** API key for DeDi authentication (required when OPENCRED_DEDI_AUTH_TYPE=api-key). */
  OPENCRED_DEDI_API_KEY: z.string().optional(),

  /** Email for DeDi bearer authentication (required when OPENCRED_DEDI_AUTH_TYPE=bearer). */
  OPENCRED_DEDI_EMAIL: z.string().email().optional(),

  /** Password for DeDi bearer authentication (required when OPENCRED_DEDI_AUTH_TYPE=bearer). */
  OPENCRED_DEDI_PASSWORD: z.string().optional(),

  /** Default DeDi namespace. Required when OPENCRED_DEDI_BASE_URL is set. */
  OPENCRED_DEDI_NAMESPACE: z.string().optional(),

  /** DeDi request timeout in milliseconds (default: 10000). */
  OPENCRED_DEDI_TIMEOUT_MS: z.coerce.number().int().min(1000).max(30000).default(10000),

  // --- Rate limiting (per-IP / per-token, in-memory buckets) ---

  /**
   * Master switch for the per-route rate limiter. The limiter is on by
   * default — every documented public deployment in the README runs behind
   * either a reverse proxy or directly exposed and benefits from the tail-
   * latency protection. Set to false to disable (e.g. when an upstream
   * gateway is already applying its own limits and you want to avoid
   * double-counting).
   */
  OPENCRED_RATE_LIMIT_ENABLED: z
    .preprocess((value) => {
      if (value === undefined || value === null || value === "") return true;
      if (typeof value === "boolean") return value;
      if (typeof value === "string") {
        const normalized = value.trim().toLowerCase();
        if (["true", "1", "yes", "on"].includes(normalized)) return true;
        if (["false", "0", "no", "off"].includes(normalized)) return false;
      }
      return value;
    }, z.boolean())
    .default(true),

  /**
   * When true, the rate limiter trusts the `X-Forwarded-For` header to
   * derive the client IP. Required when the server runs behind a reverse
   * proxy / load balancer (Cloud Run, nginx, ALB, etc.) and you want
   * per-client buckets (not per-proxy buckets). Fail-closed: when unset
   * the limiter ignores the header — otherwise any internet client could
   * spoof a unique IP per request and bypass the limit entirely.
   */
  OPENCRED_TRUST_PROXY: booleanFromString,

  /**
   * Rate-limit window in milliseconds. Per-route limits below are scaled
   * against this window. Default 60s.
   */
  OPENCRED_RATE_LIMIT_WINDOW_MS: z.coerce
    .number()
    .int()
    .min(1000)
    .max(60 * 60 * 1000)
    .default(60_000),

  /**
   * Max requests per window for `/credentials/issue` and
   * `/credentials/batch` (the heaviest endpoints — signature path).
   */
  OPENCRED_RATE_LIMIT_ISSUE: z.coerce.number().int().min(1).default(60),

  /**
   * Max requests per window for `/credentials/verify`. Verify is lighter
   * than issue (no signature, no body buffer), so the cap is doubled.
   */
  OPENCRED_RATE_LIMIT_VERIFY: z.coerce.number().int().min(1).default(120),

  /**
   * Max requests per window for read-only routes (schemas/*, /health,
   * /metrics). High enough that legitimate dashboards and uptime probes
   * never hit it; low enough to blunt a trivial DoS.
   */
  OPENCRED_RATE_LIMIT_READ: z.coerce.number().int().min(1).default(600),

  // --- Job store (Tier 2 #5 of nfh-trust-labs/opencred#446) ---

  /**
   * Backing store for batch jobs.
   *
   *  - `memory` (default): single-process Map. Suitable for single-instance
   *    deployments — same behaviour as every release prior to this one.
   *  - `redis`: Redis-backed store keyed by job id, with Redis-managed TTL.
   *    Required for horizontal scale (multiple replicas all need to answer
   *    `GET /credentials/batch/:jobId` regardless of which replica received
   *    the original POST).
   *
   * Defaults to `memory` so the absence of a Redis is not a regression for
   * existing single-instance operators. When set to `redis`,
   * `OPENCRED_REDIS_URL` MUST also be set — startup fails closed with
   * `ConfigError` otherwise.
   */
  OPENCRED_JOB_STORE: z.enum(["memory", "redis"]).default("memory"),

  /**
   * Redis connection URL — used only when `OPENCRED_JOB_STORE=redis`.
   * Accepts the standard URL shape (`redis://`, `rediss://` for TLS).
   * May embed credentials inline (`redis://user:pass@host:6379/0`).
   *
   * SECURITY: This URL frequently contains credentials. The server logs
   * only the host/port descriptor, never the full URL. See `safeRedisInfo`
   * in `apps/server/src/batch/job-store/factory.ts`.
   */
  OPENCRED_REDIS_URL: z.string().url().optional(),

  // --- OpenTelemetry tracing (Tier 3 #10 of nfh-trust-labs/opencred#446) ---

  /**
   * Master switch for OpenTelemetry tracing. Defaults to **false** for
   * back-compat with existing single-instance deployments — every release
   * before this one ran without tracing instrumentation. When enabled,
   * critical-path spans (`http.server.duration`, `batch.row.process`,
   * `signer.sign`, `verify.*`, `dedi.*`) are emitted to the configured
   * collector. Standard OpenTelemetry environment variables apply:
   *
   *   - `OTEL_EXPORTER_OTLP_ENDPOINT` — collector URL (e.g. `http://otel:4318`).
   *     When unset, spans are emitted to a no-op exporter so the tracer
   *     overhead is still bounded (no network calls). Useful for tests
   *     that exercise the in-memory exporter via `setInMemoryExporter`.
   *   - `OTEL_SERVICE_NAME` — defaults to `opencred-server`.
   *   - `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` — sampler config
   *     (e.g. `parentbased_traceidratio` + `0.1` for 10% sampling).
   *
   * SECURITY: Spans MUST NOT carry private key material, signing buffers,
   * or credential subject PII. The instrumentation helpers in
   * `src/observability/` enforce this contract — see signer-span.ts.
   */
  OPENCRED_OTEL_ENABLED: booleanFromString,

  /**
   * Read-only mode (Tier 3 #9 of nfh-trust-labs/opencred#446).
   *
   * When `true`, the server refuses every write endpoint (issue, batch,
   * revoke, keys/publish) with a `405 Method Not Allowed` response. The
   * read surface (verify, keys/resolve, schemas, contexts, health,
   * metrics) stays enabled. This implements the "dedicated read tier"
   * deployment pattern: an operator runs a replica fleet without the
   * signing key, in front of (or instead of) a CDN, to scale verification
   * traffic without paying the signing-cost overhead on every node.
   *
   * Fail-closed semantics:
   *  - The enforcement middleware uses a denylist of *write* paths so a
   *    new write endpoint added later, without updating the list, is
   *    blocked by default — the read surface is the explicit allowlist,
   *    not the implicit one. See `apps/server/src/middleware/read-only.ts`.
   *  - The flag is checked at every request. Toggling it via a runtime
   *    env hot-reload is not supported (config is cached at startup), but
   *    a rolling restart picks up the new value.
   */
  OPENCRED_READ_ONLY: booleanFromString,

  /**
   * Whether to verify the Redis server's TLS certificate when using
   * `rediss://`. Defaults to `true` (verify). Operators MUST opt in
   * explicitly to disable verification — there is no silent fall-through
   * via an empty string.
   */
  OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED: z
    .preprocess((value) => {
      // SECURITY: empty string MUST fall through to the default (true).
      // The generic `booleanFromString` helper coerces "" to false, which
      // would silently disable TLS verification — a common footgun when an
      // env template variable fails to expand. Override the preprocess here
      // so only explicit "false" / "0" / "no" / "off" actually opt-out.
      if (value === undefined || value === null || value === "") return true;
      if (typeof value === "boolean") return value;
      if (typeof value === "string") {
        const normalized = value.trim().toLowerCase();
        if (normalized === "") return true;
        if (["true", "1", "yes", "on"].includes(normalized)) return true;
        if (["false", "0", "no", "off"].includes(normalized)) return false;
      }
      return value;
    }, z.boolean())
    .default(true),
});

export type ServerConfig = z.infer<typeof configSchema>;

/**
 * ConfigError — thrown by loadConfig() when the environment is misconfigured
 * in a security-relevant way (e.g. authentication missing). Uses the
 * OpenCredError hierarchy so the message is sanitized for HTTP responses,
 * but at startup these errors are surfaced to stderr and the process exits.
 */
export class ConfigError extends OpenCredError {
  constructor(message: string) {
    super(message, "CONFIG_ERROR", 500);
    this.name = "ConfigError";
  }
}

let cachedConfig: ServerConfig | null = null;

/**
 * Parse and validate environment variables. Throws on invalid config.
 * Result is cached after first call.
 *
 * SECURITY: Enforces the auth fail-closed invariant. After this function
 * returns successfully, exactly ONE of the following is true:
 *
 *  1. `OPENCRED_API_KEY` is set and `OPENCRED_DEV_MODE_NO_AUTH` is unset —
 *     all protected endpoints require a Bearer token.
 *  2. `OPENCRED_DEV_MODE_NO_AUTH=true` is set, `OPENCRED_API_KEY` is unset,
 *     and `NODE_ENV` is not `production`.
 *
 * Any other combination is rejected here. In particular, setting BOTH the
 * API key AND the dev-mode opt-out is refused regardless of `NODE_ENV` —
 * otherwise the auth middleware (which checks dev-mode first) would silently
 * bypass the explicitly configured API key, undoing the entire fail-closed
 * invariant. See nfh-trust-labs/opencred#312.
 */
export function loadConfig(): ServerConfig {
  if (cachedConfig) return cachedConfig;
  const parsed = configSchema.parse(process.env);

  const isProduction = process.env.NODE_ENV === "production";

  // Defense in depth: never allow the dev-mode opt-out in production.
  if (parsed.OPENCRED_DEV_MODE_NO_AUTH && isProduction) {
    throw new ConfigError(
      "OPENCRED_DEV_MODE_NO_AUTH=true is not permitted when NODE_ENV=production. " +
        "Unset OPENCRED_DEV_MODE_NO_AUTH and provide a real OPENCRED_API_KEY.",
    );
  }

  // Mutually exclusive: setting BOTH the API key AND the dev-mode opt-out
  // would let an operator believe the API key is enforced while the auth
  // middleware silently calls next() via the dev-mode branch. Refuse the
  // ambiguous combination here so the operator must pick one explicitly.
  if (parsed.OPENCRED_API_KEY && parsed.OPENCRED_DEV_MODE_NO_AUTH) {
    throw new ConfigError(
      "OPENCRED_API_KEY and OPENCRED_DEV_MODE_NO_AUTH are mutually exclusive. " +
        "Pick exactly one: set OPENCRED_API_KEY for real authentication, OR set " +
        "OPENCRED_DEV_MODE_NO_AUTH=true (and unset OPENCRED_API_KEY) for local " +
        "development only.",
    );
  }

  // Fail closed: require explicit credentials or an explicit dev-mode opt-out.
  if (!parsed.OPENCRED_API_KEY && !parsed.OPENCRED_DEV_MODE_NO_AUTH) {
    throw new ConfigError(
      "OPENCRED_API_KEY is required. " +
        "Set OPENCRED_API_KEY to a strong, randomly generated bearer token before " +
        "starting the server. For local development only, you may instead set " +
        "OPENCRED_DEV_MODE_NO_AUTH=true to disable authentication; this is REFUSED " +
        "when NODE_ENV=production.",
    );
  }

  // --- Issuer identity cross-field validation ---
  // When method=web, the domain is required (the whole point of did:web).
  // When method=key, the domain is ignored if set (don't make this an
  // error — operators may flip methods without scrubbing env vars).
  if (parsed.OPENCRED_ISSUER_DID_METHOD === "web" && !parsed.OPENCRED_ISSUER_DOMAIN) {
    throw new ConfigError(
      "OPENCRED_ISSUER_DOMAIN is required when OPENCRED_ISSUER_DID_METHOD=web. " +
        "Set it to the public domain that hosts your did:web DID document " +
        "(e.g., 'issuer.example.com'). The server expects to find " +
        "`https://<domain>/.well-known/did.json` reachable at startup.",
    );
  }

  // DeDi-as-bundled-hosting requires DeDi to be configured.
  // When method=key the flag has no effect; ignore it silently (matching the
  // OPENCRED_ISSUER_DOMAIN rule above — operators may flip methods without
  // scrubbing env vars). When DeDi itself is not configured, the flag has no
  // fallback meaning, so we still throw.
  if (parsed.OPENCRED_DEDI_HOST_DID_DOC && parsed.OPENCRED_ISSUER_DID_METHOD === "web") {
    if (!parsed.OPENCRED_DEDI_BASE_URL) {
      throw new ConfigError(
        "OPENCRED_DEDI_HOST_DID_DOC=true requires DeDi to be configured. " +
          "Set OPENCRED_DEDI_BASE_URL, OPENCRED_DEDI_AUTH_TYPE, and OPENCRED_DEDI_NAMESPACE.",
      );
    }
  }

  // --- DeDi cross-field validation ---
  // When DeDi is enabled (BASE_URL set), auth type and namespace are required.
  // When auth type is api-key, the DeDi API key is required.
  // When auth type is bearer, email and password are required.
  if (parsed.OPENCRED_DEDI_BASE_URL) {
    if (!parsed.OPENCRED_DEDI_AUTH_TYPE) {
      throw new ConfigError(
        "OPENCRED_DEDI_AUTH_TYPE is required when OPENCRED_DEDI_BASE_URL is set. " +
          "Set OPENCRED_DEDI_AUTH_TYPE to 'api-key' or 'bearer'.",
      );
    }
    if (!parsed.OPENCRED_DEDI_NAMESPACE) {
      throw new ConfigError(
        "OPENCRED_DEDI_NAMESPACE is required when OPENCRED_DEDI_BASE_URL is set.",
      );
    }
    if (parsed.OPENCRED_DEDI_AUTH_TYPE === "api-key" && !parsed.OPENCRED_DEDI_API_KEY) {
      throw new ConfigError(
        "OPENCRED_DEDI_API_KEY is required when OPENCRED_DEDI_AUTH_TYPE=api-key.",
      );
    }
    if (parsed.OPENCRED_DEDI_AUTH_TYPE === "bearer") {
      if (!parsed.OPENCRED_DEDI_EMAIL) {
        throw new ConfigError(
          "OPENCRED_DEDI_EMAIL is required when OPENCRED_DEDI_AUTH_TYPE=bearer.",
        );
      }
      if (!parsed.OPENCRED_DEDI_PASSWORD) {
        throw new ConfigError(
          "OPENCRED_DEDI_PASSWORD is required when OPENCRED_DEDI_AUTH_TYPE=bearer.",
        );
      }
    }
  }

  // --- Job store cross-field validation ---
  // When OPENCRED_JOB_STORE=redis, OPENCRED_REDIS_URL must be set.
  // Refuse to start with a half-configured Redis store — a silent fall-
  // back to memory would let an operator believe their jobs were
  // shareable across replicas when they weren't.
  if (parsed.OPENCRED_JOB_STORE === "redis" && !parsed.OPENCRED_REDIS_URL) {
    throw new ConfigError(
      "OPENCRED_REDIS_URL is required when OPENCRED_JOB_STORE=redis. " +
        "Set OPENCRED_REDIS_URL to a redis:// (or rediss:// for TLS) URL. " +
        "If you do not need horizontal scale, set OPENCRED_JOB_STORE=memory " +
        "(or omit the variable entirely — memory is the default).",
    );
  }

  cachedConfig = parsed;
  return cachedConfig;
}

/**
 * Get the current config. Throws if loadConfig() has not been called.
 */
export function getConfig(): ServerConfig {
  if (!cachedConfig) {
    throw new Error("Config not loaded. Call loadConfig() first.");
  }
  return cachedConfig;
}

/**
 * Reset cached config (for testing only).
 */
export function resetConfig(): void {
  cachedConfig = null;
}
