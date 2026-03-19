/**
 * Pino logger setup for the OpenCred server.
 *
 * SECURITY: Never log key material. Only log key IDs and fingerprints.
 */

import pino from "pino";
import { getConfig } from "./config.js";

let loggerInstance: pino.Logger | null = null;

export function createLogger(): pino.Logger {
  const config = getConfig();
  loggerInstance = pino({
    level: config.OPENCRED_LOG_LEVEL,
    formatters: {
      level(label) {
        return { level: label };
      },
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
  return loggerInstance;
}

export function getLogger(): pino.Logger {
  if (!loggerInstance) {
    throw new Error("Logger not initialized. Call createLogger() first.");
  }
  return loggerInstance;
}
