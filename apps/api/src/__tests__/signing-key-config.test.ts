import { describe, it, expect, afterEach } from "vitest";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { writeFileSync, unlinkSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { LocalSigningKeyProvider } from "@opencred/crypto";
import { loadConfig } from "@opencred/shared";

/**
 * Generate a fresh ECDSA P-256 key pair and return the private key as PEM.
 */
function generateTestPem(): string {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return privateKey.export({ type: "pkcs8", format: "pem" }) as string;
}

describe("Signing key configuration", () => {
  const tempFiles: string[] = [];

  afterEach(() => {
    for (const f of tempFiles) {
      if (existsSync(f)) unlinkSync(f);
    }
    tempFiles.length = 0;
  });

  it("generates a random key when no signing key env vars are set", () => {
    const provider = new LocalSigningKeyProvider();
    const key = provider.getActiveKey();

    expect(key.id).toMatch(/^did:key:z/);
    expect(key.algorithm).toBe("P-256");
    expect(key.privateKey).toBeDefined();
    expect(key.publicKey).toBeDefined();
  });

  it("loads key from PEM string when OPENCRED_SIGNING_KEY_PEM is set", () => {
    const pem = generateTestPem();

    const provider = new LocalSigningKeyProvider({ privateKeyPem: pem });
    const key = provider.getActiveKey();

    expect(key.id).toMatch(/^did:key:z/);
    expect(key.algorithm).toBe("P-256");

    // A second provider with the same PEM must produce the same key ID
    const provider2 = new LocalSigningKeyProvider({ privateKeyPem: pem });
    expect(provider2.getActiveKey().id).toBe(key.id);
  });

  it("loads key from file when OPENCRED_SIGNING_KEY_PATH is set", () => {
    const pem = generateTestPem();
    const filePath = join(tmpdir(), `opencred-test-key-${Date.now()}.pem`);
    writeFileSync(filePath, pem, "utf-8");
    tempFiles.push(filePath);

    const provider = new LocalSigningKeyProvider({ privateKeyPath: filePath });
    const key = provider.getActiveKey();

    expect(key.id).toMatch(/^did:key:z/);
    expect(key.algorithm).toBe("P-256");

    // Must match the key loaded from the same PEM directly
    const providerDirect = new LocalSigningKeyProvider({ privateKeyPem: pem });
    expect(providerDirect.getActiveKey().id).toBe(key.id);
  });

  it("loaded key produces valid signatures", () => {
    const pem = generateTestPem();

    const provider = new LocalSigningKeyProvider({ privateKeyPem: pem });
    const key = provider.getActiveKey();

    const data = new Uint8Array(Buffer.from("test payload for signing"));
    const signature = provider.sign(data);

    // Verify the signature using Node.js crypto directly
    const verifier = createVerify("SHA256");
    verifier.update(data);

    // LocalSigningKeyProvider produces IEEE P1363 (raw r||s) signatures,
    // so we need to convert to DER for Node.js verify or use dsaEncoding option
    const isValid = verifier.verify(
      { key: key.publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature),
    );
    expect(isValid).toBe(true);
  });

  it("two providers without env vars generate different keys", () => {
    const provider1 = new LocalSigningKeyProvider();
    const provider2 = new LocalSigningKeyProvider();

    expect(provider1.getActiveKey().id).not.toBe(provider2.getActiveKey().id);
  });

  it("config schema accepts optional OPENCRED_SIGNING_KEY_PEM", () => {
    const pem = generateTestPem();
    const config = loadConfig({ OPENCRED_SIGNING_KEY_PEM: pem });
    expect(config.OPENCRED_SIGNING_KEY_PEM).toBe(pem);
  });

  it("config schema accepts optional OPENCRED_SIGNING_KEY_PATH", () => {
    const config = loadConfig({ OPENCRED_SIGNING_KEY_PATH: "/etc/opencred/key.pem" });
    expect(config.OPENCRED_SIGNING_KEY_PATH).toBe("/etc/opencred/key.pem");
  });

  it("config defaults to undefined when signing key env vars are absent", () => {
    const config = loadConfig({});
    expect(config.OPENCRED_SIGNING_KEY_PEM).toBeUndefined();
    expect(config.OPENCRED_SIGNING_KEY_PATH).toBeUndefined();
  });
});
