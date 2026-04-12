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
