/**
 * Multi-algorithm tests for the updated software signer module.
 *
 * Tests the multi-algorithm support added to the software signer:
 * detectKeyFormat, detectKeyAlgorithm, buildSigner, buildSignerFromPfx,
 * createSoftwareSigner (PFX), createSoftwareSignerFromBuffer (PFX),
 * and sign+verify roundtrips for P-256, P-384, and RSA-2048.
 *
 * All ephemeral test keys are generated in-process using crypto.generateKeyPairSync.
 * PFX fixture files are loaded from test/fixtures/.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync, createPublicKey, createVerify, verify, constants } from "node:crypto";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  detectKeyFormat,
  detectKeyAlgorithm,
  buildSigner,
  buildSignerFromPfx,
  createSoftwareSigner,
  createSoftwareSignerFromBuffer,
} from "../software-signer.js";
import { CryptoError } from "@opencred/shared";

// ----- Fixture paths -----
const fixturesDir = path.resolve(__dirname, "../../test/fixtures");
const TEST_PASSWORD = "test123";

function loadFixture(filename: string): Buffer {
  return readFileSync(path.join(fixturesDir, filename));
}

// ----- Ephemeral test keys -----

// P-256
const ec256Pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const ec256Pem = ec256Pair.privateKey.export({ format: "pem", type: "pkcs8" }) as string;
const ec256Jwk = ec256Pair.privateKey.export({ format: "jwk" });
const ec256Der = ec256Pair.privateKey.export({ format: "der", type: "pkcs8" });

// P-384
const ec384Pair = generateKeyPairSync("ec", { namedCurve: "P-384" });
const ec384Pem = ec384Pair.privateKey.export({ format: "pem", type: "pkcs8" }) as string;

// Ed25519
const ed25519Pair = generateKeyPairSync("ed25519");
const ed25519Jwk = ed25519Pair.privateKey.export({ format: "jwk" });

// RSA-2048
const rsa2048Pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const rsa2048Pem = rsa2048Pair.privateKey.export({ format: "pem", type: "pkcs8" }) as string;

// ----- Temp directory for file-based tests -----
let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(path.join(os.tmpdir(), "opencred-multi-algo-test-"));

  writeFileSync(path.join(tmpDir, "ec256.pem"), ec256Pem);
  writeFileSync(path.join(tmpDir, "ec256.json"), JSON.stringify(ec256Jwk));
  writeFileSync(path.join(tmpDir, "ec256.der"), ec256Der);
  writeFileSync(path.join(tmpDir, "ec384.pem"), ec384Pem);
  writeFileSync(path.join(tmpDir, "ed25519.json"), JSON.stringify(ed25519Jwk));
  writeFileSync(path.join(tmpDir, "rsa2048.pem"), rsa2048Pem);
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

// ----- detectKeyFormat -----

describe("detectKeyFormat", () => {
  it('should return "pfx" for files with .pfx extension hint', () => {
    // Binary content that does not look like PEM or JWK
    const binaryContent = Buffer.from([0x30, 0x82, 0x01, 0x00]);
    expect(detectKeyFormat(binaryContent, "my-key.pfx")).toBe("pfx");
  });

  it('should return "pfx" for files with .p12 extension hint', () => {
    const binaryContent = Buffer.from([0x30, 0x82, 0x01, 0x00]);
    expect(detectKeyFormat(binaryContent, "issuer-dsc.p12")).toBe("pfx");
  });

  it('should return "pfx" for .PFX extension (case insensitive)', () => {
    const binaryContent = Buffer.from([0x30, 0x82, 0x01, 0x00]);
    expect(detectKeyFormat(binaryContent, "KEY.PFX")).toBe("pfx");
  });

  it('should return "pem" for PEM content even with .pfx hint', () => {
    // PEM detection takes priority over filename hint
    const pemContent = Buffer.from(
      "-----BEGIN PRIVATE KEY-----\nbase64data\n-----END PRIVATE KEY-----",
    );
    expect(detectKeyFormat(pemContent, "misleading.pfx")).toBe("pem");
  });

  it('should return "pem" for PEM content', () => {
    expect(detectKeyFormat(Buffer.from(ec256Pem))).toBe("pem");
  });

  it('should return "jwk" for JWK content', () => {
    expect(detectKeyFormat(Buffer.from(JSON.stringify(ec256Jwk)))).toBe("jwk");
  });

  it('should return "pkcs8-der" for binary content without hint', () => {
    expect(detectKeyFormat(Buffer.from(ec256Der))).toBe("pkcs8-der");
  });

  it('should return "pkcs8-der" for binary content with non-pfx hint', () => {
    expect(detectKeyFormat(Buffer.from(ec256Der), "key.bin")).toBe("pkcs8-der");
  });
});

// ----- detectKeyAlgorithm -----

describe("detectKeyAlgorithm", () => {
  it("should detect P-256 from an EC public key", () => {
    const pubKey = createPublicKey(ec256Pair.privateKey);
    expect(detectKeyAlgorithm(pubKey)).toBe("P-256");
  });

  it("should detect P-384 from an EC public key", () => {
    const pubKey = createPublicKey(ec384Pair.privateKey);
    expect(detectKeyAlgorithm(pubKey)).toBe("P-384");
  });

  it("should detect RSA-2048 from an RSA public key", () => {
    const pubKey = createPublicKey(rsa2048Pair.privateKey);
    expect(detectKeyAlgorithm(pubKey)).toBe("RSA-2048");
  });

  it("should detect RSA-4096 from a 4096-bit RSA key", () => {
    const rsa4096 = generateKeyPairSync("rsa", { modulusLength: 4096 });
    const pubKey = createPublicKey(rsa4096.privateKey);
    expect(detectKeyAlgorithm(pubKey)).toBe("RSA-4096");
  });

  it("should detect Ed25519 from an OKP public key", () => {
    const ed25519 = generateKeyPairSync("ed25519");
    const pubKey = createPublicKey(ed25519.privateKey);
    expect(detectKeyAlgorithm(pubKey)).toBe("Ed25519");
  });
});

// ----- buildSigner -----

describe("buildSigner", () => {
  it("should build a signer from RSA key with did:jwk ID", () => {
    const pubKey = createPublicKey(rsa2048Pair.privateKey);
    const signer = buildSigner(rsa2048Pair.privateKey, pubKey);

    expect(signer.algorithm).toBe("RSA-2048");
    expect(signer.type).toBe("software");
    // RSA keys use did:jwk
    expect(signer.id).toMatch(/^did:jwk:/);
    expect(signer.id).toContain("#");
    expect(signer.metadata.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should build a signer from P-256 key with did:key ID", () => {
    const pubKey = createPublicKey(ec256Pair.privateKey);
    const signer = buildSigner(ec256Pair.privateKey, pubKey);

    expect(signer.algorithm).toBe("P-256");
    expect(signer.id).toMatch(/^did:key:z/);
  });

  it("should build a signer from P-384 key with did:key ID", () => {
    const pubKey = createPublicKey(ec384Pair.privateKey);
    const signer = buildSigner(ec384Pair.privateKey, pubKey);

    expect(signer.algorithm).toBe("P-384");
    expect(signer.id).toMatch(/^did:key:z/);
  });

  it("should build a signer from Ed25519 key with did:key ID", () => {
    const pubKey = createPublicKey(ed25519Pair.privateKey);
    const signer = buildSigner(ed25519Pair.privateKey, pubKey);

    expect(signer.algorithm).toBe("Ed25519");
    expect(signer.id).toMatch(/^did:key:z/);
    expect(signer.type).toBe("software");
    expect(signer.metadata.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should include certificate chain in metadata when provided", () => {
    const pubKey = createPublicKey(rsa2048Pair.privateKey);
    const chain = ["-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"];
    const signer = buildSigner(rsa2048Pair.privateKey, pubKey, "test-label", chain);

    expect(signer.metadata.certificateChain).toEqual(chain);
    expect(signer.metadata.label).toBe("test-label");
  });

  it("should omit certificateChain from metadata when not provided", () => {
    const pubKey = createPublicKey(ec256Pair.privateKey);
    const signer = buildSigner(ec256Pair.privateKey, pubKey);

    expect(signer.metadata.certificateChain).toBeUndefined();
  });
});

// ----- buildSignerFromPfx -----

describe("buildSignerFromPfx", () => {
  it("should build a signer from RSA PFX", () => {
    const buffer = loadFixture("test-rsa2048.pfx");
    const signer = buildSignerFromPfx(buffer, TEST_PASSWORD, "RSA PFX");

    expect(signer.algorithm).toBe("RSA-2048");
    expect(signer.type).toBe("software");
    expect(signer.id).toMatch(/^did:jwk:/);
    expect(signer.metadata.label).toBe("RSA PFX");
    // PFX should include the certificate chain
    expect(signer.metadata.certificateChain).toBeDefined();
    expect(signer.metadata.certificateChain!.length).toBeGreaterThanOrEqual(1);
  });

  it("should build a signer from EC P-256 PFX", () => {
    const buffer = loadFixture("test-ec256.pfx");
    const signer = buildSignerFromPfx(buffer, TEST_PASSWORD);

    expect(signer.algorithm).toBe("P-256");
    expect(signer.id).toMatch(/^did:key:z/);
  });

  it("should build a signer from EC P-384 PFX", () => {
    const buffer = loadFixture("test-ec384.pfx");
    const signer = buildSignerFromPfx(buffer, TEST_PASSWORD);

    expect(signer.algorithm).toBe("P-384");
    expect(signer.id).toMatch(/^did:key:z/);
  });
});

// ----- createSoftwareSigner (file path) with multi-algo -----

describe("createSoftwareSigner (multi-algorithm)", () => {
  it("should load P-384 PEM key", () => {
    const { signer, format } = createSoftwareSigner(path.join(tmpDir, "ec384.pem"));

    expect(format).toBe("pem");
    expect(signer.algorithm).toBe("P-384");
    expect(signer.type).toBe("software");
    expect(signer.id).toMatch(/^did:key:z/);
  });

  it("should load Ed25519 JWK key", () => {
    const { signer, format } = createSoftwareSigner(path.join(tmpDir, "ed25519.json"));

    expect(format).toBe("jwk");
    expect(signer.algorithm).toBe("Ed25519");
    expect(signer.type).toBe("software");
    expect(signer.id).toMatch(/^did:key:z/);
  });

  it("should load RSA-2048 PEM key", () => {
    const { signer, format } = createSoftwareSigner(path.join(tmpDir, "rsa2048.pem"));

    expect(format).toBe("pem");
    expect(signer.algorithm).toBe("RSA-2048");
    expect(signer.type).toBe("software");
    expect(signer.id).toMatch(/^did:jwk:/);
  });

  it("should load PFX file with password", () => {
    // Copy a PFX fixture to tmpDir so createSoftwareSigner can read it
    const pfxBuffer = loadFixture("test-ec256.pfx");
    const pfxPath = path.join(tmpDir, "key.pfx");
    writeFileSync(pfxPath, pfxBuffer);

    const { signer, format } = createSoftwareSigner(pfxPath, "EC PFX Key", TEST_PASSWORD);

    expect(format).toBe("pfx");
    expect(signer.algorithm).toBe("P-256");
    expect(signer.metadata.label).toBe("EC PFX Key");
  });

  it("should throw CryptoError when PFX file has no password", () => {
    const pfxBuffer = loadFixture("test-rsa2048.pfx");
    const pfxPath = path.join(tmpDir, "rsa.pfx");
    writeFileSync(pfxPath, pfxBuffer);

    expect(() => createSoftwareSigner(pfxPath)).toThrow(CryptoError);
    expect(() => createSoftwareSigner(pfxPath)).toThrow(/PFX import requires a password/);
  });
});

// ----- createSoftwareSignerFromBuffer -----

describe("createSoftwareSignerFromBuffer (multi-algorithm)", () => {
  it("should create P-384 signer from PEM buffer", () => {
    const { signer, format } = createSoftwareSignerFromBuffer(Buffer.from(ec384Pem));

    expect(format).toBe("pem");
    expect(signer.algorithm).toBe("P-384");
  });

  it("should create Ed25519 signer from JWK buffer", () => {
    const { signer, format } = createSoftwareSignerFromBuffer(
      Buffer.from(JSON.stringify(ed25519Jwk)),
    );

    expect(format).toBe("jwk");
    expect(signer.algorithm).toBe("Ed25519");
  });

  it("should create RSA signer from PEM buffer", () => {
    const { signer, format } = createSoftwareSignerFromBuffer(Buffer.from(rsa2048Pem));

    expect(format).toBe("pem");
    expect(signer.algorithm).toBe("RSA-2048");
  });

  it("should create signer from PFX buffer with filenameHint and password", () => {
    const pfxBuffer = loadFixture("test-ec384.pfx");
    const { signer, format } = createSoftwareSignerFromBuffer(
      pfxBuffer,
      "PFX Label",
      TEST_PASSWORD,
      "imported.pfx",
    );

    expect(format).toBe("pfx");
    expect(signer.algorithm).toBe("P-384");
    expect(signer.metadata.label).toBe("PFX Label");
  });

  it("should throw CryptoError when PFX buffer has no password", () => {
    const pfxBuffer = loadFixture("test-rsa2048.pfx");

    expect(() =>
      createSoftwareSignerFromBuffer(pfxBuffer, undefined, undefined, "key.pfx"),
    ).toThrow(CryptoError);
    expect(() =>
      createSoftwareSignerFromBuffer(pfxBuffer, undefined, undefined, "key.pfx"),
    ).toThrow(/PFX import requires a password/);
  });
});

// ----- Sign + Verify Roundtrips -----

describe("sign + verify roundtrip", () => {
  const testData = new Uint8Array(64).fill(0xab);

  it("P-256: signature should be 64 bytes and verify", async () => {
    const pubKey = createPublicKey(ec256Pair.privateKey);
    const signer = buildSigner(ec256Pair.privateKey, pubKey);

    const signature = await signer.sign(testData);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);

    // Verify using Node.js crypto
    const verifier = createVerify("SHA256");
    verifier.update(testData);
    const valid = verifier.verify(
      { key: pubKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature),
    );
    expect(valid).toBe(true);
  });

  it("P-384: signature should be 96 bytes and verify", async () => {
    const pubKey = createPublicKey(ec384Pair.privateKey);
    const signer = buildSigner(ec384Pair.privateKey, pubKey);

    const signature = await signer.sign(testData);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(96);

    // Verify using Node.js crypto
    const verifier = createVerify("SHA384");
    verifier.update(testData);
    const valid = verifier.verify(
      { key: pubKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature),
    );
    expect(valid).toBe(true);
  });

  it("RSA-2048: signature should be 256 bytes and verify", async () => {
    const pubKey = createPublicKey(rsa2048Pair.privateKey);
    const signer = buildSigner(rsa2048Pair.privateKey, pubKey);

    const signature = await signer.sign(testData);

    expect(signature).toBeInstanceOf(Uint8Array);
    // RSA-2048 produces a 256-byte signature (2048 bits / 8)
    expect(signature.length).toBe(256);

    // Verify using Node.js crypto with PSS padding
    const verifier = createVerify("SHA256");
    verifier.update(testData);
    const valid = verifier.verify(
      {
        key: pubKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      },
      Buffer.from(signature),
    );
    expect(valid).toBe(true);
  });

  it("Ed25519: signature should be 64 bytes and verify", async () => {
    const pubKey = createPublicKey(ed25519Pair.privateKey);
    const signer = buildSigner(ed25519Pair.privateKey, pubKey);

    const signature = await signer.sign(testData);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);

    // Verify using Node.js crypto.verify for Ed25519
    const valid = verify(null, testData, pubKey, Buffer.from(signature));
    expect(valid).toBe(true);
  });

  it("PFX-loaded RSA signer should produce valid signatures", async () => {
    const pfxBuffer = loadFixture("test-rsa2048.pfx");
    const signer = buildSignerFromPfx(pfxBuffer, TEST_PASSWORD);

    const signature = await signer.sign(testData);
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(256);
  });

  it("PFX-loaded EC P-256 signer should produce valid signatures", async () => {
    const pfxBuffer = loadFixture("test-ec256.pfx");
    const signer = buildSignerFromPfx(pfxBuffer, TEST_PASSWORD);

    const signature = await signer.sign(testData);
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });

  it("PFX-loaded EC P-384 signer should produce valid signatures", async () => {
    const pfxBuffer = loadFixture("test-ec384.pfx");
    const signer = buildSignerFromPfx(pfxBuffer, TEST_PASSWORD);

    const signature = await signer.sign(testData);
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(96);
  });

  it("different data should produce different signatures (ECDSA)", async () => {
    const pubKey = createPublicKey(ec256Pair.privateKey);
    const signer = buildSigner(ec256Pair.privateKey, pubKey);

    const data1 = new Uint8Array(32).fill(0x00);
    const data2 = new Uint8Array(32).fill(0xff);

    const sig1 = await signer.sign(data1);
    const sig2 = await signer.sign(data2);

    expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(false);
  });

  it("different data should produce different signatures (RSA)", async () => {
    const pubKey = createPublicKey(rsa2048Pair.privateKey);
    const signer = buildSigner(rsa2048Pair.privateKey, pubKey);

    const data1 = new Uint8Array(32).fill(0x00);
    const data2 = new Uint8Array(32).fill(0xff);

    const sig1 = await signer.sign(data1);
    const sig2 = await signer.sign(data2);

    expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(false);
  });
});

// ----- Security: metadata never exposes key material -----

describe("signer metadata (security)", () => {
  it("RSA signer metadata should never contain private key material", () => {
    const pubKey = createPublicKey(rsa2048Pair.privateKey);
    const signer = buildSigner(rsa2048Pair.privateKey, pubKey);

    const meta = signer.metadata;
    const metaStr = JSON.stringify(meta);

    expect(meta).not.toHaveProperty("privateKey");
    expect(meta).not.toHaveProperty("d");
    expect(meta).not.toHaveProperty("p");
    expect(meta).not.toHaveProperty("q");
    expect(metaStr).not.toContain('"d"');
    expect(metaStr).not.toContain('"dp"');
    expect(metaStr).not.toContain('"dq"');
    expect(metaStr).not.toContain('"qi"');

    expect(meta.id).toBeDefined();
    expect(meta.algorithm).toBe("RSA-2048");
    expect(meta.type).toBe("software");
    expect(meta.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("P-384 signer metadata should never contain private key material", () => {
    const pubKey = createPublicKey(ec384Pair.privateKey);
    const signer = buildSigner(ec384Pair.privateKey, pubKey);

    const meta = signer.metadata;
    const metaStr = JSON.stringify(meta);

    expect(meta).not.toHaveProperty("privateKey");
    expect(metaStr).not.toContain('"d"');

    expect(meta.id).toBeDefined();
    expect(meta.algorithm).toBe("P-384");
    expect(meta.type).toBe("software");
    expect(meta.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
});
