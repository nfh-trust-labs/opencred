/**
 * Factory for creating a DeDiClient from server configuration.
 *
 * Returns null when DeDi env vars are not configured — the server
 * functions without DeDi (revocation checks are simply skipped).
 *
 * SECURITY: DeDi auth values are NEVER logged.
 * Only the base URL and auth type are logged at startup.
 */

import { DeDiClient } from "@opencred/dedi-client";
import type { DeDiLogger } from "@opencred/dedi-client";
import type { ServerConfig } from "./config.js";
import type pino from "pino";

/**
 * Bridge a pino logger to the DeDiLogger interface expected by the client.
 *
 * The DeDiLogger interface uses positional args `(msg, ...args)` while pino
 * uses `(obj?, msg?, ...args)`. We pass the extra args as a `data` field in
 * the first-argument object so pino serialises them without losing context.
 */
function bridgePinoToDeDiLogger(pinoLogger: pino.Logger): DeDiLogger {
  return {
    info(msg: string, ...args: unknown[]) {
      pinoLogger.info({ dedi: true, data: args.length ? args[0] : undefined }, msg);
    },
    debug(msg: string, ...args: unknown[]) {
      pinoLogger.debug({ dedi: true, data: args.length ? args[0] : undefined }, msg);
    },
    warn(msg: string, ...args: unknown[]) {
      pinoLogger.warn({ dedi: true, data: args.length ? args[0] : undefined }, msg);
    },
    error(msg: string, ...args: unknown[]) {
      pinoLogger.error({ dedi: true, data: args.length ? args[0] : undefined }, msg);
    },
  };
}

/**
 * Create a DeDiClient from the server config, or return null if DeDi is
 * not configured (OPENCRED_DEDI_BASE_URL is not set).
 */
export function createDeDiClientFromConfig(
  config: ServerConfig,
  logger: pino.Logger,
): DeDiClient | null {
  if (!config.OPENCRED_DEDI_BASE_URL) {
    return null;
  }

  const authType = config.OPENCRED_DEDI_AUTH_TYPE;

  let auth:
    | { type: "api-key"; apiKey: string }
    | { type: "bearer"; email: string; password: string };

  if (authType === "api-key") {
    // Config validation guarantees the relevant field is set when auth type is api-key.
    auth = { type: "api-key", apiKey: config.OPENCRED_DEDI_API_KEY! };
  } else {
    // Config validation guarantees email + pw are set when auth type is bearer.
    auth = {
      type: "bearer",
      email: config.OPENCRED_DEDI_EMAIL!,
      password: config.OPENCRED_DEDI_PASSWORD!,
    };
  }

  const dediLogger = bridgePinoToDeDiLogger(logger);

  return new DeDiClient({
    baseUrl: config.OPENCRED_DEDI_BASE_URL,
    auth,
    defaultNamespace: config.OPENCRED_DEDI_NAMESPACE,
    timeoutMs: config.OPENCRED_DEDI_TIMEOUT_MS,
    circuitBreakerThreshold: 5,
    maxRetries: 2,
    logger: dediLogger,
  });
}
