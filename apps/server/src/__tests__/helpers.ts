/**
 * Shared test helpers for server tests.
 */

import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Hono } from "hono";
import { ZodError } from "zod";

import { loadConfig, resetConfig } from "../config.js";
import { createLogger, resetLogger } from "../logger.js";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { health } from "../routes/health.js";
import { schemas } from "../routes/schemas.js";
import { credentials } from "../routes/credentials.js";
import { batch } from "../routes/batch.js";
import { revocation } from "../routes/revocation.js";
import { packaging } from "../routes/packaging.js";
import { keys } from "../routes/keys.js";
import { computeFingerprint, deriveDidKeyIdFromPublicKey } from "@opencred/signing";
import type { Signer, SignerMetadata } from "@opencred/signing";
import { sign as ecSign } from "node:crypto";

// ---------------------------------------------------------------------------
// Test key generation
// ---------------------------------------------------------------------------

export interface TestKeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  signer: Signer;
  pemPath: string;
}

/**
 * Generate a P-256 test key pair and write the private key to a temp PEM file.
 * Returns a Signer that can be used with setActiveSigner().
 */
export function generateTestKey(): TestKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  const testDir = join(tmpdir(), "opencred-server-tests");
  mkdirSync(testDir, { recursive: true });
  const pemPath = join(testDir, `test-key-${Date.now()}.pem`);
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  writeFileSync(pemPath, pem);

  const fingerprint = computeFingerprint(publicKey);
  const id = deriveDidKeyIdFromPublicKey(publicKey);

  const metadata: SignerMetadata = {
    id,
    algorithm: "P-256",
    type: "software",
    fingerprint,
    label: "test-key",
  };

  const signer: Signer = {
    id,
    algorithm: "P-256",
    type: "software",
    metadata,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      const sig = ecSign(null, Buffer.from(data), {
        key: privateKey,
        dsaEncoding: "ieee-p1363",
      });
      return new Uint8Array(sig);
    },
  };

  return { privateKey, publicKey, signer, pemPath };
}

// ---------------------------------------------------------------------------
// App factory for testing
// ---------------------------------------------------------------------------

/** Default API key used by tests that do not care about the auth path. */
export const DEFAULT_TEST_API_KEY = "test-api-key-default";

/**
 * Create a fresh Hono app with all routes and middleware,
 * initializing config and logger from current env vars.
 *
 * The server now refuses to start without OPENCRED_API_KEY (or an explicit
 * dev-mode opt-out), so this helper either sets an API key or enables the
 * dev-mode flag — never both unset.
 *
 * Options:
 *  - `apiKey`     — explicit API key string. Auth is enforced.
 *  - `devModeNoAuth: true` — enable OPENCRED_DEV_MODE_NO_AUTH=true. Auth is bypassed.
 *  - neither      — defaults to apiKey = DEFAULT_TEST_API_KEY.
 */
export function createTestApp(opts?: { apiKey?: string; devModeNoAuth?: boolean }): Hono {
  // Reset singletons
  resetConfig();
  resetLogger();

  // Wipe any prior auth-related env vars so previous tests don't bleed in.
  delete process.env.OPENCRED_API_KEY;
  delete process.env.OPENCRED_DEV_MODE_NO_AUTH;
  // Tests run in NODE_ENV=test by default; force it so the dev-mode opt-out
  // is permitted (it is refused when NODE_ENV=production).
  if (process.env.NODE_ENV === "production") {
    delete process.env.NODE_ENV;
  }

  if (opts?.devModeNoAuth) {
    process.env.OPENCRED_DEV_MODE_NO_AUTH = "true";
  } else if (opts?.apiKey !== undefined) {
    process.env.OPENCRED_API_KEY = opts.apiKey;
  } else {
    // Default: an API key is set so auth is enforced. Tests that need
    // unauthenticated behaviour pass devModeNoAuth: true explicitly.
    process.env.OPENCRED_API_KEY = DEFAULT_TEST_API_KEY;
  }

  // Ensure basic config is set
  if (!process.env.OPENCRED_PORT) {
    process.env.OPENCRED_PORT = "3199";
  }
  process.env.OPENCRED_LOG_LEVEL = "fatal";

  loadConfig();
  createLogger();

  const app = new Hono();

  // Global middleware
  app.use("*", authMiddleware);

  // Mount routes — both legacy ("/") and versioned ("/v1") paths.
  // Mirrors src/index.ts so the smoke test exercises the full production
  // surface (including the rejectKeyMaterial defense on every POST route).
  app.route("/", health);
  app.route("/", schemas);
  app.route("/", credentials);
  app.route("/", batch);
  app.route("/", revocation);
  app.route("/", packaging);
  app.route("/", keys);

  app.route("/v1", health);
  app.route("/v1", schemas);
  app.route("/v1", credentials);
  app.route("/v1", batch);
  app.route("/v1", revocation);
  app.route("/v1", packaging);
  app.route("/v1", keys);

  // Global error handler (same as index.ts)
  app.onError((err, c) => {
    if (err instanceof ZodError) {
      return c.json(
        {
          error: {
            code: "VALIDATION_ERROR",
            message: "Request validation failed",
            details: err.errors.map((e) => ({
              path: e.path.join("."),
              message: e.message,
            })),
          },
        },
        400,
      );
    }
    return errorHandler(err, c);
  });

  app.notFound((c) => {
    return c.json({ error: { code: "NOT_FOUND", message: "Endpoint not found" } }, 404);
  });

  return app;
}

// ---------------------------------------------------------------------------
// Credential test data
// ---------------------------------------------------------------------------

export const FUNCTIONAL_IDENTITY_SUBJECT = {
  name: "Jane Doe",
  role: "Medical Practitioner",
  validFrom: "2025-06-15T00:00:00Z",
  affiliation: { name: "Acme Medical Council" },
};

/**
 * Alias for smoke tests that were written against the legacy "education"
 * schema. The schema library replaced the generic schemas with v1 envelope
 * schemas; "functional-identity/v1" is the closest match.
 */
export const EDUCATION_SUBJECT = FUNCTIONAL_IDENTITY_SUBJECT;

export const VALID_ISSUE_REQUEST = {
  schemaId: "functional-identity/v1",
  issuerDid: "did:key:test-issuer",
  credentialSubject: FUNCTIONAL_IDENTITY_SUBJECT,
  validFrom: "2025-06-15T00:00:00Z",
  proofFormat: "vc-jwt",
};
