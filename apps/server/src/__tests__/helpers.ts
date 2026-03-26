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
import { setActiveSigner } from "../signing/key-manager.js";
import { health } from "../routes/health.js";
import { schemas } from "../routes/schemas.js";
import { credentials } from "../routes/credentials.js";
import { batch } from "../routes/batch.js";
import { revocation } from "../routes/revocation.js";
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

/**
 * Create a fresh Hono app with all routes and middleware,
 * initializing config and logger from current env vars.
 */
export function createTestApp(opts?: { apiKey?: string }): Hono {
  // Reset singletons
  resetConfig();
  resetLogger();

  // Set env vars before loading config
  if (opts?.apiKey) {
    process.env.OPENCRED_API_KEY = opts.apiKey;
  } else {
    delete process.env.OPENCRED_API_KEY;
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

  // Mount routes
  app.route("/", health);
  app.route("/", schemas);
  app.route("/", credentials);
  app.route("/", batch);
  app.route("/", revocation);

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

export const EDUCATION_SUBJECT = {
  name: "Jane Doe",
  degree: "Master of Science",
  institution: "MIT",
  dateConferred: "2025-06-15",
};

export const VALID_ISSUE_REQUEST = {
  schemaId: "education",
  issuerDid: "did:key:test-issuer",
  credentialSubject: EDUCATION_SUBJECT,
  validFrom: "2025-06-15T00:00:00Z",
  proofFormat: "vc-jwt",
};
