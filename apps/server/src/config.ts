/**
 * Server configuration — Zod schema for all environment variables.
 *
 * All configuration is loaded from environment variables at startup.
 * Sensitive values (key paths, API keys) are validated but NEVER logged.
 */

import { z } from "zod";

const configSchema = z.object({
  /** Port the HTTP server listens on. */
  OPENCRED_PORT: z.coerce.number().int().min(1).max(65535).default(3100),

  /** Bearer token for API authentication. If unset, auth is disabled. */
  OPENCRED_API_KEY: z.string().optional(),

  /** Log level for pino. */
  OPENCRED_LOG_LEVEL: z
    .enum(["fatal", "error", "warn", "info", "debug", "trace"])
    .default("info"),

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
});

export type ServerConfig = z.infer<typeof configSchema>;

let cachedConfig: ServerConfig | null = null;

/**
 * Parse and validate environment variables. Throws on invalid config.
 * Result is cached after first call.
 */
export function loadConfig(): ServerConfig {
  if (cachedConfig) return cachedConfig;
  cachedConfig = configSchema.parse(process.env);
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
