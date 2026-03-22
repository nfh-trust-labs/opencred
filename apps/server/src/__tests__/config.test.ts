/**
 * Config validation tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadConfig, resetConfig } from "../config.js";

// Save and restore env vars between tests
const originalEnv = { ...process.env };

beforeEach(() => {
  resetConfig();
});

afterEach(() => {
  // Restore original env
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("OPENCRED_")) {
      delete process.env[key];
    }
  }
  for (const [key, value] of Object.entries(originalEnv)) {
    if (key.startsWith("OPENCRED_") && value !== undefined) {
      process.env[key] = value;
    }
  }
  resetConfig();
});

describe("Config validation", () => {
  it("parses valid config with defaults", () => {
    const config = loadConfig();
    expect(config.OPENCRED_PORT).toBe(3100);
    expect(config.OPENCRED_LOG_LEVEL).toBe("info");
    expect(config.OPENCRED_KEY_LABEL).toBe("server-key");
    expect(config.OPENCRED_BATCH_ROW_LIMIT).toBe(1000);
    expect(config.OPENCRED_SESSION_TTL).toBe(14400);
    expect(config.OPENCRED_KMS_PROVIDER).toBe("none");
  });

  it("parses custom port from env", () => {
    process.env.OPENCRED_PORT = "8080";
    const config = loadConfig();
    expect(config.OPENCRED_PORT).toBe(8080);
  });

  it("parses API key from env", () => {
    process.env.OPENCRED_API_KEY = "my-secret-key";
    const config = loadConfig();
    expect(config.OPENCRED_API_KEY).toBe("my-secret-key");
  });

  it("rejects invalid port — zero", () => {
    process.env.OPENCRED_PORT = "0";
    expect(() => loadConfig()).toThrow();
  });

  it("rejects invalid port — too high", () => {
    process.env.OPENCRED_PORT = "99999";
    expect(() => loadConfig()).toThrow();
  });

  it("rejects invalid port — not a number", () => {
    process.env.OPENCRED_PORT = "abc";
    expect(() => loadConfig()).toThrow();
  });

  it("rejects invalid log level", () => {
    process.env.OPENCRED_LOG_LEVEL = "verbose";
    expect(() => loadConfig()).toThrow();
  });

  it("rejects invalid KMS provider", () => {
    process.env.OPENCRED_KMS_PROVIDER = "oracle";
    expect(() => loadConfig()).toThrow();
  });

  it("accepts valid KMS provider values", () => {
    for (const provider of ["aws", "azure", "gcp", "none"]) {
      resetConfig();
      process.env.OPENCRED_KMS_PROVIDER = provider;
      const config = loadConfig();
      expect(config.OPENCRED_KMS_PROVIDER).toBe(provider);
    }
  });

  it("rejects invalid session TTL below minimum", () => {
    process.env.OPENCRED_SESSION_TTL = "10";
    expect(() => loadConfig()).toThrow();
  });

  it("caches config after first call", () => {
    const config1 = loadConfig();
    process.env.OPENCRED_PORT = "9999";
    const config2 = loadConfig();
    expect(config2.OPENCRED_PORT).toBe(config1.OPENCRED_PORT);
  });
});
