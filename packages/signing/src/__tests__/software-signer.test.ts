import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { generateKeyPairSync, createVerify, constants } from "node:crypto";
import {
  detectKeyFormat,
  detectKeyAlgorithm,
  buildSigner,
  buildSignerFromPfx,
  createSoftwareSignerFromBuffer,
} from "../software-signer.js";
import { CryptoError } from "@opencred/shared";

const FIXTURES_DIR = resolve(import.meta.dirname, "../../test/fixtures");

describe("detectKeyFormat", () => {
  it("should detect PEM format", () => {
    const content = Buffer.from(
      "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----",
    );
    expect(detectKeyFormat(content)).toBe("pem");
  });

  it("should detect JWK format", () => {
    const content = Buffer.from(JSON.stringify({ kty: "EC", crv: "P-256" }));
    expect(detectKeyFormat(content)).toBe("jwk");
  });

  it("should detect PFX via filename hint .pfx", () => {
    const content = Buffer.from([0x30, 0x82, 0x00, 0x01]);
    expect(detectKeyFormat(content, "my-cert.pfx")).toBe("pfx");
  });

  it("should detect PFX via filename hint .p12", () => {
    const content = Buffer.from([0x30, 0x82, 0x00, 0x01]);
    expect(detectKeyFormat(content, "/path/to/my-cert.P12")).toBe("pfx");
  });

  it("should fall back to pkcs8-der for binary without hint", () => {
    const content = Buffer.from([0x30, 0x82, 0x00, 0x01]);
    expect(detectKeyFormat(content)).toBe("pkcs8-der");
  });

  it("should detect PFX from real PFX file with hint", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-rsa2048.pfx"));
    expect(detectKeyFormat(buffer, "test-rsa2048.pfx")).toBe("pfx");
  });
});

describe("detectKeyAlgorithm", () => {
  it("should detect P-256", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(detectKeyAlgorithm(publicKey)).toBe("P-256");
  });

  it("should detect P-384", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    expect(detectKeyAlgorithm(publicKey)).toBe("P-384");
  });

  it("should detect RSA-2048", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(detectKeyAlgorithm(publicKey)).toBe("RSA-2048");
  });

  it("should throw for unsupported EC curve", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "secp521r1" });
    expect(() => detectKeyAlgorithm(publicKey)).toThrow(CryptoError);
  });
});

describe("buildSigner", () => {
  it("should create a P-256 signer with did:key ID", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signer = buildSigner(privateKey, publicKey, "test-p256");

    expect(signer.algorithm).toBe("P-256");
    expect(signer.id).toMatch(/^did:key:z/);
    expect(signer.type).toBe("software");
    expect(signer.metadata.label).toBe("test-p256");
    expect(signer.metadata.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should create a P-384 signer with did:key ID", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const signer = buildSigner(privateKey, publicKey, "test-p384");

    expect(signer.algorithm).toBe("P-384");
    expect(signer.id).toMatch(/^did:key:z/);
  });

  it("should create an RSA-2048 signer with did:jwk ID", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const signer = buildSigner(privateKey, publicKey, "test-rsa");

    expect(signer.algorithm).toBe("RSA-2048");
    expect(signer.id).toMatch(/^did:jwk:/);
    expect(signer.id).toContain("#0");
  });

  it("should include certificate chain in metadata when provided", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const chain = ["-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"];
    const signer = buildSigner(privateKey, publicKey, "test", chain);

    expect(signer.metadata.certificateChain).toEqual(chain);
  });

  it("should not include certificateChain when empty array", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signer = buildSigner(privateKey, publicKey, "test", []);

    expect(signer.metadata.certificateChain).toBeUndefined();
  });
});

describe("sign + verify round trip", () => {
  const testData = new Uint8Array(Buffer.from("test data for signing"));

  it("P-256 sign produces 64-byte signature that verifies", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signer = buildSigner(privateKey, publicKey);

    const signature = await signer.sign(testData);
    expect(signature.length).toBe(64);

    const verifier = createVerify("SHA256");
    verifier.update(testData);
    const valid = verifier.verify(
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature),
    );
    expect(valid).toBe(true);
  });

  it("P-384 sign produces 96-byte signature that verifies", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const signer = buildSigner(privateKey, publicKey);

    const signature = await signer.sign(testData);
    expect(signature.length).toBe(96);

    const verifier = createVerify("SHA384");
    verifier.update(testData);
    const valid = verifier.verify(
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature),
    );
    expect(valid).toBe(true);
  });

  it("RSA-2048 sign produces valid PSS signature that verifies", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const signer = buildSigner(privateKey, publicKey);

    const signature = await signer.sign(testData);
    expect(signature.length).toBe(256);

    const verifier = createVerify("SHA256");
    verifier.update(testData);
    const valid = verifier.verify(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
      },
      Buffer.from(signature),
    );
    expect(valid).toBe(true);
  });
});

describe("buildSignerFromPfx", () => {
  it("should create a signer from RSA-2048 PFX", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-rsa2048.pfx"));
    const signer = buildSignerFromPfx(buffer, "test123", "rsa-pfx");

    expect(signer.algorithm).toBe("RSA-2048");
    expect(signer.id).toMatch(/^did:jwk:/);
    expect(signer.metadata.certificateChain).toBeDefined();
    expect(signer.metadata.certificateChain!.length).toBeGreaterThanOrEqual(1);
  });

  it("should create a signer from EC P-256 PFX", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-ec256.pfx"));
    const signer = buildSignerFromPfx(buffer, "test123", "ec-pfx");

    expect(signer.algorithm).toBe("P-256");
    expect(signer.id).toMatch(/^did:key:z/);
  });

  it("PFX signer can sign and verify", async () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-rsa2048.pfx"));
    const signer = buildSignerFromPfx(buffer, "test123");

    const data = new Uint8Array(Buffer.from("pfx sign test"));
    const signature = await signer.sign(data);
    expect(signature.length).toBeGreaterThan(0);
  });
});

describe("createSoftwareSignerFromBuffer", () => {
  it("should create signer from PFX buffer with password and hint", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-ec256.pfx"));
    const { signer, format } = createSoftwareSignerFromBuffer(
      buffer,
      "ec-pfx",
      "test123",
      "cert.pfx",
    );

    expect(format).toBe("pfx");
    expect(signer.algorithm).toBe("P-256");
  });

  it("should throw when PFX detected but no password provided", () => {
    const buffer = readFileSync(resolve(FIXTURES_DIR, "test-ec256.pfx"));
    expect(() => createSoftwareSignerFromBuffer(buffer, "label", undefined, "cert.pfx")).toThrow(
      "PFX import requires a password",
    );
  });
});
