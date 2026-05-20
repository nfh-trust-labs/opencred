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

describe("Config — DeDi cross-field validation", () => {
  it("accepts config when OPENCRED_DEDI_BASE_URL is not set", () => {
    expect(() => loadConfig()).not.toThrow();
  });

  it("requires OPENCRED_DEDI_AUTH_TYPE when OPENCRED_DEDI_BASE_URL is set", () => {
    process.env.OPENCRED_DEDI_BASE_URL = "https://dedi.example.com";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_DEDI_AUTH_TYPE is required/);
  });

  it("requires OPENCRED_DEDI_NAMESPACE when OPENCRED_DEDI_BASE_URL is set", () => {
    process.env.OPENCRED_DEDI_BASE_URL = "https://dedi.example.com";
    process.env.OPENCRED_DEDI_AUTH_TYPE = "api-key";
    process.env.OPENCRED_DEDI_API_KEY = "some-key";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_DEDI_NAMESPACE is required/);
  });

  it("requires OPENCRED_DEDI_API_KEY when auth type is api-key", () => {
    process.env.OPENCRED_DEDI_BASE_URL = "https://dedi.example.com";
    process.env.OPENCRED_DEDI_AUTH_TYPE = "api-key";
    process.env.OPENCRED_DEDI_NAMESPACE = "test-ns";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_DEDI_API_KEY is required/);
  });

  it("requires OPENCRED_DEDI_EMAIL when auth type is bearer", () => {
    process.env.OPENCRED_DEDI_BASE_URL = "https://dedi.example.com";
    process.env.OPENCRED_DEDI_AUTH_TYPE = "bearer";
    process.env.OPENCRED_DEDI_NAMESPACE = "test-ns";
    process.env.OPENCRED_DEDI_PASSWORD = "pw";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_DEDI_EMAIL is required/);
  });

  it("requires OPENCRED_DEDI_PASSWORD when auth type is bearer", () => {
    process.env.OPENCRED_DEDI_BASE_URL = "https://dedi.example.com";
    process.env.OPENCRED_DEDI_AUTH_TYPE = "bearer";
    process.env.OPENCRED_DEDI_NAMESPACE = "test-ns";
    process.env.OPENCRED_DEDI_EMAIL = "user@example.com";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_DEDI_PASSWORD is required/);
  });

  it("accepts valid DeDi config with api-key auth", () => {
    process.env.OPENCRED_DEDI_BASE_URL = "https://dedi.example.com";
    process.env.OPENCRED_DEDI_AUTH_TYPE = "api-key";
    process.env.OPENCRED_DEDI_API_KEY = "my-dedi-key";
    process.env.OPENCRED_DEDI_NAMESPACE = "test-ns";
    const config = loadConfig();
    expect(config.OPENCRED_DEDI_BASE_URL).toBe("https://dedi.example.com");
    expect(config.OPENCRED_DEDI_AUTH_TYPE).toBe("api-key");
    expect(config.OPENCRED_DEDI_NAMESPACE).toBe("test-ns");
    expect(config.OPENCRED_DEDI_TIMEOUT_MS).toBe(10000);
  });

  it("accepts valid DeDi config with bearer auth", () => {
    process.env.OPENCRED_DEDI_BASE_URL = "https://dedi.example.com";
    process.env.OPENCRED_DEDI_AUTH_TYPE = "bearer";
    process.env.OPENCRED_DEDI_EMAIL = "user@example.com";
    process.env.OPENCRED_DEDI_PASSWORD = "test-pw";
    process.env.OPENCRED_DEDI_NAMESPACE = "test-ns";
    const config = loadConfig();
    expect(config.OPENCRED_DEDI_AUTH_TYPE).toBe("bearer");
    expect(config.OPENCRED_DEDI_EMAIL).toBe("user@example.com");
  });

  it("uses default timeout of 10000ms", () => {
    const config = loadConfig();
    expect(config.OPENCRED_DEDI_TIMEOUT_MS).toBe(10000);
  });

  it("accepts custom OPENCRED_DEDI_TIMEOUT_MS", () => {
    process.env.OPENCRED_DEDI_TIMEOUT_MS = "5000";
    const config = loadConfig();
    expect(config.OPENCRED_DEDI_TIMEOUT_MS).toBe(5000);
  });
});

describe("Config — issuer identity (DID method)", () => {
  it("defaults to OPENCRED_ISSUER_DID_METHOD=key", () => {
    const config = loadConfig();
    expect(config.OPENCRED_ISSUER_DID_METHOD).toBe("key");
    expect(config.OPENCRED_ISSUER_DOMAIN).toBeUndefined();
  });

  it("accepts OPENCRED_ISSUER_DID_METHOD=web with a domain", () => {
    process.env.OPENCRED_ISSUER_DID_METHOD = "web";
    process.env.OPENCRED_ISSUER_DOMAIN = "issuer.example.com";
    const config = loadConfig();
    expect(config.OPENCRED_ISSUER_DID_METHOD).toBe("web");
    expect(config.OPENCRED_ISSUER_DOMAIN).toBe("issuer.example.com");
  });

  it("rejects OPENCRED_ISSUER_DID_METHOD=web without a domain", () => {
    process.env.OPENCRED_ISSUER_DID_METHOD = "web";
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_ISSUER_DOMAIN is required/);
  });

  it("rejects unknown DID method values", () => {
    process.env.OPENCRED_ISSUER_DID_METHOD = "ion";
    expect(() => loadConfig()).toThrow();
  });

  it("ignores OPENCRED_ISSUER_DOMAIN when method=key (does not error)", () => {
    // Operators may flip methods without scrubbing env vars — don't punish them.
    process.env.OPENCRED_ISSUER_DID_METHOD = "key";
    process.env.OPENCRED_ISSUER_DOMAIN = "leftover.example.com";
    const config = loadConfig();
    expect(config.OPENCRED_ISSUER_DID_METHOD).toBe("key");
  });

  it("accepts OPENCRED_DEDI_HOST_DID_DOC=true with method=web and DeDi configured", () => {
    process.env.OPENCRED_ISSUER_DID_METHOD = "web";
    process.env.OPENCRED_ISSUER_DOMAIN = "issuer.example.com";
    process.env.OPENCRED_DEDI_HOST_DID_DOC = "true";
    process.env.OPENCRED_DEDI_BASE_URL = "https://dedi.example.com";
    process.env.OPENCRED_DEDI_AUTH_TYPE = "api-key";
    process.env.OPENCRED_DEDI_API_KEY = "test-key";
    process.env.OPENCRED_DEDI_NAMESPACE = "test-ns";
    const config = loadConfig();
    expect(config.OPENCRED_DEDI_HOST_DID_DOC).toBe(true);
  });

  it("accepts OPENCRED_DEDI_HOST_DID_DOC=true when method=key (flag ignored, no throw)", () => {
    // Matches the philosophy of the OPENCRED_ISSUER_DOMAIN cross-field rule:
    // operators may flip methods without scrubbing env vars, so leftover
    // hosting-related flags are silently ignored under method=key.
    process.env.OPENCRED_ISSUER_DID_METHOD = "key";
    process.env.OPENCRED_DEDI_HOST_DID_DOC = "true";
    const config = loadConfig();
    expect(config.OPENCRED_ISSUER_DID_METHOD).toBe("key");
    expect(config.OPENCRED_DEDI_HOST_DID_DOC).toBe(true);
  });

  it("rejects OPENCRED_DEDI_HOST_DID_DOC=true without DeDi configured", () => {
    process.env.OPENCRED_ISSUER_DID_METHOD = "web";
    process.env.OPENCRED_ISSUER_DOMAIN = "issuer.example.com";
    process.env.OPENCRED_DEDI_HOST_DID_DOC = "true";
    expect(() => loadConfig()).toThrow(/requires DeDi to be configured/);
  });

  // --- Job store (Tier 2 #5 of nfh-trust-labs/opencred#446) ---

  it("defaults OPENCRED_JOB_STORE to memory", () => {
    const config = loadConfig();
    expect(config.OPENCRED_JOB_STORE).toBe("memory");
  });

  it("accepts OPENCRED_JOB_STORE=redis with a valid OPENCRED_REDIS_URL", () => {
    process.env.OPENCRED_JOB_STORE = "redis";
    process.env.OPENCRED_REDIS_URL = "redis://localhost:6379";
    const config = loadConfig();
    expect(config.OPENCRED_JOB_STORE).toBe("redis");
    expect(config.OPENCRED_REDIS_URL).toBe("redis://localhost:6379");
  });

  it("rejects OPENCRED_JOB_STORE=redis when OPENCRED_REDIS_URL is unset", () => {
    process.env.OPENCRED_JOB_STORE = "redis";
    delete process.env.OPENCRED_REDIS_URL;
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_REDIS_URL is required/);
  });

  it("rejects unknown OPENCRED_JOB_STORE values", () => {
    process.env.OPENCRED_JOB_STORE = "etcd";
    expect(() => loadConfig()).toThrow();
  });

  it("defaults OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED to true (verify by default)", () => {
    const config = loadConfig();
    expect(config.OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED).toBe(true);
  });

  it("honours OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED=false (explicit opt-out)", () => {
    process.env.OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED = "false";
    const config = loadConfig();
    expect(config.OPENCRED_REDIS_TLS_REJECT_UNAUTHORIZED).toBe(false);
  });
});
