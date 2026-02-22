import type { EnvConfig } from "@opencred/shared";
import pino from "pino";

export function makeTestConfig(overrides: Partial<EnvConfig> = {}): EnvConfig {
  return {
    NODE_ENV: "test",
    PORT: 3000,
    LOG_LEVEL: "fatal",
    DEDI_API_TIMEOUT_MS: 10000,
    SESSION_TTL_MS: 14400000,
    SESSION_SWEEP_INTERVAL_MS: 60000,
    JWT_ISSUER: "opencred",
    JWT_EXPIRY_SECONDS: 3600,
    CORS_ORIGIN: "http://localhost:5173",
    ...overrides,
  } as EnvConfig;
}

export function makeTestLogger() {
  return pino({ level: "silent" });
}
