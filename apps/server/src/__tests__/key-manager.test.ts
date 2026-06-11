/**
 * Tests for `loadSigningKey` — specifically the verification-method override
 * path that fixes issue #632 (JWT `kid` was `did:key:…` even with
 * `OPENCRED_ISSUER_DID_METHOD=web`).
 *
 * Covers:
 *   1. method=key + EC key → signer.id stays `did:key:…`
 *   2. method=web + EC key → signer.id flips to `did:web:<domain>#key-0`
 *      and `signer.metadata.id` matches.
 *   3. method=web + RSA key → same did:web override (not `did:jwk:…`).
 *   4. method=web with no OPENCRED_ISSUER_DOMAIN — guarded earlier by
 *      `loadConfig` (the config validator rejects this combo); covered
 *      here only as documentation of the contract.
 *
 * The test writes a temporary key file because `createSoftwareSigner` reads
 * from disk. The file is removed in `afterEach`.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, unlinkSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { loadConfig, resetConfig } from "../config.js";
import { createLogger, resetLogger } from "../logger.js";
import { loadSigningKey, setActiveSigner } from "../signing/key-manager.js";

const originalEnv = { ...process.env };

let tempDir: string;
let keyPath: string;

function setBaselineEnv(): void {
  // Strip every OPENCRED_* var so individual tests start from a clean slate.
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("OPENCRED_")) delete process.env[key];
  }
  process.env.OPENCRED_API_KEY = "test-key-manager-api-key";
}

function writeP256JwkKey(): string {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = privateKey.export({ format: "jwk" });
  const path = join(tempDir, "p256.jwk");
  writeFileSync(path, JSON.stringify(jwk), { mode: 0o600 });
  return path;
}

function writeRsa2048PemKey(): string {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
  const path = join(tempDir, "rsa.pem");
  writeFileSync(path, pem, { mode: 0o600 });
  return path;
}

beforeEach(() => {
  resetConfig();
  resetLogger();
  setActiveSigner(null);
  setBaselineEnv();
  // Force log level low enough that loadSigningKey's info logs don't pollute
  // the test output. createLogger reads OPENCRED_LOG_LEVEL from config, so
  // set it BEFORE loadConfig() in each test (those that call loadConfig).
  process.env.OPENCRED_LOG_LEVEL = "fatal";
  tempDir = mkdtempSync(join(tmpdir(), "opencred-key-manager-test-"));
});

afterEach(() => {
  try {
    if (keyPath) unlinkSync(keyPath);
  } catch {
    /* ignore */
  }
  setActiveSigner(null);
  resetConfig();
  // Restore env
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("OPENCRED_")) delete process.env[key];
  }
  for (const [key, value] of Object.entries(originalEnv)) {
    if (key.startsWith("OPENCRED_") && value !== undefined) {
      process.env[key] = value;
    }
  }
});

describe("loadSigningKey — issuer DID method override (#632)", () => {
  it("leaves signer.id as did:key for method=key (default)", () => {
    keyPath = writeP256JwkKey();
    process.env.OPENCRED_KEY_PATH = keyPath;
    process.env.OPENCRED_ISSUER_DID_METHOD = "key";
    loadConfig();
    createLogger();

    const signer = loadSigningKey();
    expect(signer).not.toBeNull();
    expect(signer!.id).toMatch(/^did:key:z/);
    expect(signer!.metadata.id).toBe(signer!.id);
  });

  it("flips signer.id to did:web for method=web with EC key", () => {
    keyPath = writeP256JwkKey();
    process.env.OPENCRED_KEY_PATH = keyPath;
    process.env.OPENCRED_ISSUER_DID_METHOD = "web";
    process.env.OPENCRED_ISSUER_DOMAIN = "issuer.example.org";
    loadConfig();
    createLogger();

    const signer = loadSigningKey();
    expect(signer).not.toBeNull();
    expect(signer!.id).toBe("did:web:issuer.example.org#key-0");
    expect(signer!.metadata.id).toBe("did:web:issuer.example.org#key-0");
    // Algorithm still derived from the actual key bytes.
    expect(signer!.algorithm).toBe("P-256");
  });

  it("flips signer.id to did:web for method=web with RSA key (no longer did:jwk)", () => {
    keyPath = writeRsa2048PemKey();
    process.env.OPENCRED_KEY_PATH = keyPath;
    process.env.OPENCRED_ISSUER_DID_METHOD = "web";
    process.env.OPENCRED_ISSUER_DOMAIN = "rsa-issuer.example.org";
    loadConfig();
    createLogger();

    const signer = loadSigningKey();
    expect(signer).not.toBeNull();
    expect(signer!.id).toBe("did:web:rsa-issuer.example.org#key-0");
    expect(signer!.metadata.id).toBe("did:web:rsa-issuer.example.org#key-0");
    expect(signer!.algorithm).toBe("RSA-2048");
    // Critically, the id must NOT be a did:jwk — the old behaviour silently
    // produced did:jwk for RSA, mismatching the published did:web doc.
    expect(signer!.id).not.toMatch(/^did:jwk:/);
  });

  it("uses fragment '#key-0' to match generateDidWebDocument's primary key", () => {
    keyPath = writeP256JwkKey();
    process.env.OPENCRED_KEY_PATH = keyPath;
    process.env.OPENCRED_ISSUER_DID_METHOD = "web";
    process.env.OPENCRED_ISSUER_DOMAIN = "fragment-check.example.org";
    loadConfig();
    createLogger();

    const signer = loadSigningKey();
    // generateDidWebDocument emits `#key-0`; the rotate path's
    // `nextFragmentId = #key-{maxN+1}` depends on this being the seed value.
    expect(signer!.id.split("#")[1]).toBe("key-0");
  });

  it("returns null when OPENCRED_KEY_PATH is not configured", () => {
    process.env.OPENCRED_ISSUER_DID_METHOD = "key";
    loadConfig();
    createLogger();

    const signer = loadSigningKey();
    expect(signer).toBeNull();
  });
});
