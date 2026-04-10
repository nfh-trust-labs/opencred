/**
 * Auth middleware tests.
 *
 * Covers:
 *  - Bearer-token enforcement when an API key is configured.
 *  - Public health endpoints reachable without auth.
 *  - The fail-closed invariant for the unauthenticated case (issue #312):
 *      - server refuses to start when neither OPENCRED_API_KEY nor
 *        OPENCRED_DEV_MODE_NO_AUTH is set;
 *      - explicit dev-mode opt-out lets the server start (with a warning)
 *        and exposes protected endpoints;
 *      - dev-mode opt-out is REFUSED when NODE_ENV=production.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createTestApp, generateTestKey } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { ConfigError, loadConfig, resetConfig } from "../config.js";
import { resetLogger } from "../logger.js";
import type { Hono } from "hono";

const TEST_API_KEY = "test-api-key-12345";
const testKey = generateTestKey();

const originalNodeEnv = process.env.NODE_ENV;

afterEach(() => {
  // Restore env so other tests are unaffected.
  delete process.env.OPENCRED_API_KEY;
  delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
  if (originalNodeEnv !== undefined) {
    process.env.NODE_ENV = originalNodeEnv;
  } else {
    delete process.env.NODE_ENV;
  }
  resetConfig();
  resetLogger();
});

describe("Auth middleware — with API key configured", () => {
  let app: Hono;

  beforeEach(() => {
    app = createTestApp({ apiKey: TEST_API_KEY });
    setActiveSigner(testKey.signer);
  });

  it("rejects requests without Authorization header with 401", async () => {
    const res = await app.request("/schemas");
    expect(res.status).toBe(401);

    const body = (await res.json()) as Record<string, unknown>;
    expect((body as { error: { code: string } }).error.code).toBe("AUTHENTICATION_ERROR");
  });

  it("rejects requests with wrong Bearer token with 401", async () => {
    const res = await app.request("/schemas", {
      headers: { Authorization: "Bearer wrong-key" },
    });
    expect(res.status).toBe(401);

    const body = (await res.json()) as Record<string, unknown>;
    expect((body as { error: { code: string } }).error.code).toBe("AUTHENTICATION_ERROR");
  });

  it("rejects requests with invalid Authorization format with 401", async () => {
    const res = await app.request("/schemas", {
      headers: { Authorization: "Basic abc123" },
    });
    expect(res.status).toBe(401);
  });

  it("passes requests with correct Bearer token", async () => {
    const res = await app.request("/schemas", {
      headers: { Authorization: `Bearer ${TEST_API_KEY}` },
    });
    expect(res.status).toBe(200);
  });

  it("rejects credential issuance without Bearer token with 401", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schemaId: "education", credentialSubject: {} }),
    });
    expect(res.status).toBe(401);
  });

  it("allows /health without auth even when API key is set", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
  });

  it("allows /v1/health without auth even when API key is set", async () => {
    const res = await app.request("/v1/health");
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
  });

  it("requires auth on /v1/keys", async () => {
    const res = await app.request("/v1/keys");
    expect(res.status).toBe(401);
  });

  it("passes /v1/keys with correct Bearer token", async () => {
    const res = await app.request("/v1/keys", {
      headers: { Authorization: `Bearer ${TEST_API_KEY}` },
    });
    expect(res.status).toBe(200);
  });
});

describe("Auth middleware — fail-closed when nothing is configured (issue #312)", () => {
  beforeEach(() => {
    // Clean slate. The other test files use createTestApp() which sets one
    // of the two flags; here we want neither, so we drive loadConfig()
    // directly to assert the fail-fast behaviour.
    resetConfig();
    resetLogger();
    delete process.env.OPENCRED_API_KEY;
    delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
    process.env.OPENCRED_PORT = "3199";
    process.env.OPENCRED_LOG_LEVEL = "fatal";
    if (process.env.NODE_ENV === "production") {
      delete process.env.NODE_ENV;
    }
  });

  it("loadConfig() throws ConfigError when no API key and no dev-mode opt-out", () => {
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(/OPENCRED_API_KEY is required/);
  });

  it("does NOT silently allow requests through when nothing is configured", () => {
    // The previous behaviour (issue #312): authMiddleware short-circuited
    // with `await next(); return;` whenever no API key was set, exposing
    // every protected endpoint. The fix is fail-fast in loadConfig(), so the
    // server cannot reach the request-handling stage at all.
    let didStart = false;
    try {
      // createTestApp() forces an API key by default; bypass that and call
      // loadConfig directly with the empty environment.
      loadConfig();
      didStart = true;
    } catch {
      // Expected: ConfigError.
    }
    expect(didStart).toBe(false);
  });
});

describe("Auth middleware — explicit dev-mode opt-out", () => {
  let app: Hono;

  beforeEach(() => {
    app = createTestApp({ devModeNoAuth: true });
    setActiveSigner(testKey.signer);
  });

  it("loadConfig() succeeds with dev-mode opt-out and no API key", () => {
    // createTestApp already loaded the config; just confirm shape.
    const config = loadConfig();
    expect(config.OPENCRED_DEV_MODE_NO_AUTH).toBe(true);
    expect(config.OPENCRED_API_KEY).toBeUndefined();
  });

  it("allows all requests with no Authorization header (dev-mode bypass)", async () => {
    const res = await app.request("/schemas");
    expect(res.status).toBe(200);
  });

  it("allows credential issuance without Bearer token in dev mode", async () => {
    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        schemaId: "education",
        issuerDid: "did:key:test-issuer",
        credentialSubject: {
          name: "Jane Doe",
          degree: "BSc",
          institution: "Test U",
          dateConferred: "2025-06-15",
        },
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    // Either 200 (issued) or 400 (validation), but never 401.
    expect(res.status).not.toBe(401);
  });

  it("allows /health without auth in dev mode", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);
  });
});

describe("Auth middleware — dev-mode REFUSED in production", () => {
  beforeEach(() => {
    resetConfig();
    resetLogger();
    delete process.env.OPENCRED_API_KEY;
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
    process.env.NODE_ENV = "production";
    process.env.OPENCRED_PORT = "3199";
    process.env.OPENCRED_LOG_LEVEL = "fatal";
  });

  it("loadConfig() throws ConfigError when dev mode + production", () => {
    expect(() => loadConfig()).toThrow(ConfigError);
    expect(() => loadConfig()).toThrow(
      /OPENCRED_DEV_MODE_NO_AUTH=true is not permitted when NODE_ENV=production/,
    );
  });

  it("loadConfig() also throws when both API key and dev-mode are set in production", () => {
    process.env.OPENCRED_API_KEY = "real-key";
    expect(() => loadConfig()).toThrow(ConfigError);
  });
});
