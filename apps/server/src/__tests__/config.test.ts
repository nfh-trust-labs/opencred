/**
 * Config validation tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ConfigError, loadConfig, resetConfig } from "../config.js";

// Save and restore env vars between tests
const originalEnv = { ...process.env };
const originalNodeEnv = process.env.NODE_ENV;

beforeEach(() => {
  resetConfig();
  // Default to a known-good auth setting so individual cases only need to
  // override the variables they care about. The auth-fail-closed cases below
  // explicitly remove these.
  process.env.OPENCRED_API_KEY = "test-config-api-key";
  delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
  // Tests run in NODE_ENV=test by default. Force it off "production" so the
  // dev-mode tests can flip it on individually.
  if (process.env.NODE_ENV === "production") {
    delete process.env.NODE_ENV;
  }
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
  if (originalNodeEnv !== undefined) {
    process.env.NODE_ENV = originalNodeEnv;
  } else {
    delete process.env.NODE_ENV;
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
    expect(config.OPENCRED_DEV_MODE_NO_AUTH).toBe(false);
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

describe("Config — auth fail-closed invariant (issue #312)", () => {
  it("refuses to start when OPENCRED_API_KEY is unset and dev mode is off", () => {
    delete process.env.OPENCRED_API_KEY;
    delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_API_KEY is required/);
  });

  it("refuses to start when OPENCRED_API_KEY is the empty string", () => {
    process.env.OPENCRED_API_KEY = "";
    delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
    // The schema min(1) constraint rejects this with a ZodError, before the
    // ConfigError fail-closed check runs. Either way, the server cannot
    // boot — which is what we care about for issue #312.
    expect(() => loadConfig()).toThrow();
  });

  it("starts when OPENCRED_API_KEY is set", () => {
    process.env.OPENCRED_API_KEY = "real-key";
    expect(() => loadConfig()).not.toThrow();
    const config = loadConfig();
    expect(config.OPENCRED_API_KEY).toBe("real-key");
    expect(config.OPENCRED_DEV_MODE_NO_AUTH).toBe(false);
  });

  it("starts when OPENCRED_DEV_MODE_NO_AUTH=true is set without an API key", () => {
    delete process.env.OPENCRED_API_KEY;
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
    expect(() => loadConfig()).not.toThrow();
    const config = loadConfig();
    expect(config.OPENCRED_DEV_MODE_NO_AUTH).toBe(true);
    expect(config.OPENCRED_API_KEY).toBeUndefined();
  });

  it("treats OPENCRED_DEV_MODE_NO_AUTH=1 as true", () => {
    delete process.env.OPENCRED_API_KEY;
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "1";
    expect(loadConfig().OPENCRED_DEV_MODE_NO_AUTH).toBe(true);
  });

  it("treats OPENCRED_DEV_MODE_NO_AUTH=false as false", () => {
    delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "false";
    // No API key + dev-mode false ⇒ refuse to start.
    delete process.env.OPENCRED_API_KEY;
    expect(() => loadConfig()).toThrow(ConfigError);
  });

  it("refuses OPENCRED_DEV_MODE_NO_AUTH=true when NODE_ENV=production", () => {
    delete process.env.OPENCRED_API_KEY;
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
    process.env.NODE_ENV = "production";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(
      /OPENCRED_DEV_MODE_NO_AUTH=true is not permitted when NODE_ENV=production/,
    );
  });

  it("refuses OPENCRED_DEV_MODE_NO_AUTH=true when NODE_ENV=production even with an API key", () => {
    process.env.OPENCRED_API_KEY = "real-key";
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
    process.env.NODE_ENV = "production";
    expect(() => loadConfig()).toThrow(ConfigError);
  });

  it("starts in production when only OPENCRED_API_KEY is set", () => {
    process.env.OPENCRED_API_KEY = "real-key";
    delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
    process.env.NODE_ENV = "production";
    expect(() => loadConfig()).not.toThrow();
  });

  it("ConfigError is an OpenCredError with code CONFIG_ERROR", () => {
    delete process.env.OPENCRED_API_KEY;
    delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
    let caught: unknown = null;
    try {
      loadConfig();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConfigError);
    expect((caught as ConfigError).code).toBe("CONFIG_ERROR");
  });

  // Regression: setting both OPENCRED_API_KEY and OPENCRED_DEV_MODE_NO_AUTH
  // would let the dev-mode branch in the auth middleware silently win, even
  // though the operator explicitly configured an API key. The middleware
  // checks dev-mode first, so it would call next() without ever consulting
  // the API key. loadConfig() must refuse the ambiguous combination here.
  it("refuses both OPENCRED_API_KEY and OPENCRED_DEV_MODE_NO_AUTH together (non-prod)", () => {
    process.env.OPENCRED_API_KEY = "real-key";
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
    delete process.env.NODE_ENV;
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/mutually exclusive/);
  });

  it("refuses both OPENCRED_API_KEY and OPENCRED_DEV_MODE_NO_AUTH together (NODE_ENV=test)", () => {
    process.env.OPENCRED_API_KEY = "real-key";
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
    process.env.NODE_ENV = "test";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/mutually exclusive/);
  });

  it("refuses both OPENCRED_API_KEY and OPENCRED_DEV_MODE_NO_AUTH together (NODE_ENV=staging)", () => {
    process.env.OPENCRED_API_KEY = "real-key";
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
    process.env.NODE_ENV = "staging";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/mutually exclusive/);
  });
});
