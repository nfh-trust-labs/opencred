/**
 * Tests for the DSC (Digital Signature Certificate) import module.
 *
 * Validates PFX/PEM import, certificate metadata extraction, DID derivation,
 * key storage, key listing, and the security invariant that private keys are
 * never exposed in results.
 *
 * All test keys and certificates are generated ephemerally — no key material
 * is persisted beyond the test run.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  X509Certificate,
  type KeyObject,
} from "node:crypto";
import { createRequire } from "node:module";
import {
  importPfx,
  importPem,
  extractCertificateMetadata,
  deriveDidFromPublicKey,
  getStoredKey,
  listStoredKeys,
  clearKeyStore,
} from "../main/dsc-import";
import type { DscImportResult, CertificateMetadata } from "../main/dsc-import";

// ---------------------------------------------------------------------------
// Resolve node-forge from @opencred/signing (which has it as a dependency)
// ---------------------------------------------------------------------------
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-var-requires
const forge = require("node-forge") as typeof import("node-forge");

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

/**
 * Generate a self-signed X.509 certificate bundled in a PFX buffer using
 * node-forge. This gives us a valid PFX file for testing.
 */
function generateTestPfx(
  password: string,
  opts?: {
    commonName?: string;
    organization?: string;
    country?: string;
    issuerCommonName?: string;
    validFromDate?: Date;
    validUntilDate?: Date;
  },
): { pfxBuffer: Buffer; privateKey: KeyObject; publicKey: KeyObject } {
  // Generate an RSA key pair with node-forge (PFX/ASN.1 is simpler with RSA for testing)
  const forgeKeys = forge.pki.rsa.generateKeyPair(2048);

  const cert = forge.pki.createCertificate();
  cert.publicKey = forgeKeys.publicKey;
  cert.serialNumber = "01";

  const now = opts?.validFromDate ?? new Date();
  const later = opts?.validUntilDate ?? new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
  cert.validity.notBefore = now;
  cert.validity.notAfter = later;

  const subjectAttrs = [
    { shortName: "CN", value: opts?.commonName ?? "Test DSC" },
    { shortName: "O", value: opts?.organization ?? "Test Org" },
    { shortName: "C", value: opts?.country ?? "US" },
  ];

  const issuerAttrs = [
    { shortName: "CN", value: opts?.issuerCommonName ?? "Test CA" },
    { shortName: "O", value: "Test CA Org" },
    { shortName: "C", value: "US" },
  ];

  cert.setSubject(subjectAttrs);
  cert.setIssuer(issuerAttrs);
  cert.sign(forgeKeys.privateKey, forge.md.sha256.create());

  // Create PFX
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(forgeKeys.privateKey, [cert], password, {
    algorithm: "3des",
  });
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  const pfxBuffer = Buffer.from(p12Der, "binary");

  // Convert to Node.js KeyObjects for verification
  const privatePem = forge.pki.privateKeyToPem(forgeKeys.privateKey);
  const privateKey = createPrivateKey(privatePem);
  const publicKey = createPublicKey(privateKey);

  return { pfxBuffer, privateKey, publicKey };
}

/**
 * Generate an EC P-256 key pair and return PEM strings.
 */
function generateTestEcPem(): {
  privatePem: string;
  publicPem: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
  const publicPem = publicKey.export({ format: "pem", type: "spki" }) as string;

  return { privatePem, publicPem, privateKey, publicKey };
}

/**
 * Generate a self-signed certificate PEM string using node-forge (RSA).
 * Used for testing extractCertificateMetadata with known subject/issuer fields.
 */
function generateSelfSignedCertPem(): { certPem: string; cert: X509Certificate } {
  const forgeKeys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forgeKeys.publicKey;
  cert.serialNumber = "42";

  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  cert.setSubject([
    { shortName: "CN", value: "Metadata Test" },
    { shortName: "O", value: "Metadata Org" },
    { shortName: "C", value: "DE" },
  ]);
  cert.setIssuer([
    { shortName: "CN", value: "Metadata CA" },
    { shortName: "O", value: "CA Org" },
    { shortName: "C", value: "DE" },
  ]);

  cert.sign(forgeKeys.privateKey, forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  const x509 = new X509Certificate(certPem);

  return { certPem, cert: x509 };
}

// ---------------------------------------------------------------------------
// Test suites
// ---------------------------------------------------------------------------

describe("DSC Import Module", () => {
  beforeEach(() => {
    clearKeyStore();
  });

  // -------------------------------------------------------------------------
  // PFX import
  // -------------------------------------------------------------------------
  describe("importPfx", () => {
    it("should extract key metadata and certificate metadata from a PFX file", () => {
      const password = "test-password";
      const { pfxBuffer } = generateTestPfx(password, {
        commonName: "University DSC",
        organization: "University of Testing",
        country: "AU",
        issuerCommonName: "National CA",
      });

      const result: DscImportResult = importPfx(pfxBuffer, password);

      // Key metadata
      expect(result.keyMetadata).toBeDefined();
      expect(result.keyMetadata.id).toBeTruthy();
      expect(result.keyMetadata.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(result.keyMetadata.algorithm).toBeTruthy();
      expect(result.keyMetadata.importedAt).toBeTruthy();
      expect(result.keyMetadata.format).toBe("pfx");
      expect(result.keyMetadata.source).toBe("file");

      // Certificate metadata
      expect(result.certificateMetadata).toBeDefined();
      expect(result.certificateMetadata.subject.commonName).toBe("University DSC");
      expect(result.certificateMetadata.subject.organization).toBe("University of Testing");
      expect(result.certificateMetadata.subject.country).toBe("AU");
      expect(result.certificateMetadata.issuer.commonName).toBe("National CA");
      expect(result.certificateMetadata.serialNumber).toBeTruthy();
      expect(result.certificateMetadata.validFrom).toBeTruthy();
      expect(result.certificateMetadata.validUntil).toBeTruthy();
      expect(result.certificateMetadata.keyAlgorithm).toBeTruthy();
      expect(result.certificateMetadata.thumbprint).toMatch(/^[0-9a-f]{64}$/);

      // Certificate chain
      expect(result.certificateChain).toBeInstanceOf(Array);
      expect(result.certificateChain.length).toBeGreaterThanOrEqual(1);
      expect(result.certificateChain[0].subject).toBeTruthy();
      expect(result.certificateChain[0].issuer).toBeTruthy();
      expect(result.certificateChain[0].validFrom).toBeTruthy();
      expect(result.certificateChain[0].validUntil).toBeTruthy();
    });

    it("should throw a descriptive error for wrong password", () => {
      const { pfxBuffer } = generateTestPfx("correct-password");

      expect(() => importPfx(pfxBuffer, "wrong-password")).toThrow(
        /wrong password|corrupted|decrypt/i,
      );
    });

    it("should throw a descriptive error for invalid PFX data", () => {
      const invalidBuffer = Buffer.from("this is not a PFX file");

      expect(() => importPfx(invalidBuffer, "any-password")).toThrow(/invalid|parse|ASN/i);
    });

    it("should store the imported key retrievable by ID", () => {
      const password = "store-test";
      const { pfxBuffer } = generateTestPfx(password);

      const result = importPfx(pfxBuffer, password);
      const storedKey = getStoredKey(result.keyMetadata.id);

      expect(storedKey).toBeDefined();
      expect(storedKey!.type).toBe("private");
    });
  });

  // -------------------------------------------------------------------------
  // PEM import
  // -------------------------------------------------------------------------
  describe("importPem", () => {
    it("should import an ECDSA P-256 private key from PEM", () => {
      const { privatePem } = generateTestEcPem();

      const result: DscImportResult = importPem(privatePem);

      expect(result.keyMetadata).toBeDefined();
      expect(result.keyMetadata.algorithm).toBe("ECDSA P-256");
      expect(result.keyMetadata.id).toMatch(/^did:/);
      expect(result.keyMetadata.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(result.keyMetadata.importedAt).toBeTruthy();
      expect(result.keyMetadata.format).toBe("pem");
      expect(result.keyMetadata.source).toBe("file");
    });

    it("should throw a descriptive error for non-key PEM content", () => {
      const notAKey = "-----BEGIN SOMETHING-----\nZm9vYmFy\n-----END SOMETHING-----";

      expect(() => importPem(notAKey)).toThrow(/invalid|parse|key/i);
    });

    it("should throw a descriptive error for random text (not PEM)", () => {
      expect(() => importPem("this is not PEM data at all")).toThrow(/invalid|parse|key/i);
    });

    it("should import an RSA private key from PEM", () => {
      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const rsaPem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;

      const result = importPem(rsaPem);

      expect(result.keyMetadata.algorithm).toMatch(/^RSA/);
      expect(result.keyMetadata.id).toMatch(/^did:jwk:/);
    });

    it("should handle PEM with certificate + private key concatenated", () => {
      // Generate a PEM that contains both a certificate and a private key
      const forgeKeys = forge.pki.rsa.generateKeyPair(2048);
      const cert = forge.pki.createCertificate();
      cert.publicKey = forgeKeys.publicKey;
      cert.serialNumber = "99";
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
      cert.setSubject([{ shortName: "CN", value: "Combo Test" }]);
      cert.setIssuer([{ shortName: "CN", value: "Combo CA" }]);
      cert.sign(forgeKeys.privateKey, forge.md.sha256.create());

      const certPem = forge.pki.certificateToPem(cert);
      const keyPem = forge.pki.privateKeyToPem(forgeKeys.privateKey);
      const combinedPem = certPem + "\n" + keyPem;

      const result = importPem(combinedPem);

      expect(result.keyMetadata).toBeDefined();
      expect(result.keyMetadata.algorithm).toMatch(/^RSA/);
      // Should have certificate metadata extracted from the cert block
      expect(result.certificateMetadata).toBeDefined();
      expect(result.certificateMetadata.subject.commonName).toBe("Combo Test");
    });

    it("should store the imported key retrievable by ID", () => {
      const { privatePem } = generateTestEcPem();

      const result = importPem(privatePem);
      const storedKey = getStoredKey(result.keyMetadata.id);

      expect(storedKey).toBeDefined();
      expect(storedKey!.type).toBe("private");
    });
  });

  // -------------------------------------------------------------------------
  // Certificate metadata extraction
  // -------------------------------------------------------------------------
  describe("extractCertificateMetadata", () => {
    it("should extract correct subject and issuer fields", () => {
      const { cert } = generateSelfSignedCertPem();
      const meta: CertificateMetadata = extractCertificateMetadata(cert);

      expect(meta.subject.commonName).toBe("Metadata Test");
      expect(meta.subject.organization).toBe("Metadata Org");
      expect(meta.subject.country).toBe("DE");
      expect(meta.issuer.commonName).toBe("Metadata CA");
      expect(meta.issuer.organization).toBe("CA Org");
      expect(meta.issuer.country).toBe("DE");
    });

    it("should extract serial number", () => {
      const { cert } = generateSelfSignedCertPem();
      const meta = extractCertificateMetadata(cert);

      expect(meta.serialNumber).toBeTruthy();
      // Serial number should be a hex string
      expect(meta.serialNumber).toMatch(/^[0-9A-Fa-f]+$/);
    });

    it("should extract valid date range as ISO 8601 strings", () => {
      const { cert } = generateSelfSignedCertPem();
      const meta = extractCertificateMetadata(cert);

      // validFrom and validUntil should be parseable dates
      expect(new Date(meta.validFrom).getTime()).not.toBeNaN();
      expect(new Date(meta.validUntil).getTime()).not.toBeNaN();
      expect(new Date(meta.validUntil).getTime()).toBeGreaterThan(
        new Date(meta.validFrom).getTime(),
      );
    });

    it("should extract key algorithm", () => {
      const { cert } = generateSelfSignedCertPem();
      const meta = extractCertificateMetadata(cert);

      expect(meta.keyAlgorithm).toBeTruthy();
    });

    it("should compute a SHA-256 thumbprint", () => {
      const { cert } = generateSelfSignedCertPem();
      const meta = extractCertificateMetadata(cert);

      expect(meta.thumbprint).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // -------------------------------------------------------------------------
  // DID derivation
  // -------------------------------------------------------------------------
  describe("deriveDidFromPublicKey", () => {
    it("should produce a valid did:key for EC P-256 keys", () => {
      const { publicKey } = generateTestEcPem();

      const result = deriveDidFromPublicKey(publicKey);

      expect(result.did).toMatch(/^did:key:z/);
      expect(result.verificationMethodId).toContain("#");
      expect(result.verificationMethodId).toContain(result.did);
    });

    it("should produce a valid did:jwk for RSA keys", () => {
      const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

      const result = deriveDidFromPublicKey(publicKey);

      expect(result.did).toMatch(/^did:jwk:/);
      expect(result.verificationMethodId).toBe(`${result.did}#0`);
    });

    it("should produce deterministic results for the same key", () => {
      const { publicKey } = generateTestEcPem();

      const result1 = deriveDidFromPublicKey(publicKey);
      const result2 = deriveDidFromPublicKey(publicKey);

      expect(result1.did).toBe(result2.did);
      expect(result1.verificationMethodId).toBe(result2.verificationMethodId);
    });
  });

  // -------------------------------------------------------------------------
  // Key storage
  // -------------------------------------------------------------------------
  describe("Key storage", () => {
    it("should return undefined for non-existent key IDs", () => {
      expect(getStoredKey("non-existent-id")).toBeUndefined();
    });

    it("should list all imported keys", () => {
      const { privatePem: pem1 } = generateTestEcPem();
      const { privatePem: pem2 } = generateTestEcPem();

      const result1 = importPem(pem1);
      const result2 = importPem(pem2);

      const keys = listStoredKeys();

      expect(keys.length).toBe(2);
      const ids = keys.map((k) => k.id);
      expect(ids).toContain(result1.keyMetadata.id);
      expect(ids).toContain(result2.keyMetadata.id);
    });

    it("should clear all keys when clearKeyStore is called", () => {
      const { privatePem } = generateTestEcPem();
      importPem(privatePem);

      expect(listStoredKeys().length).toBe(1);
      clearKeyStore();
      expect(listStoredKeys().length).toBe(0);
    });

    it("should store keys from PFX import", () => {
      const password = "key-store-pfx";
      const { pfxBuffer } = generateTestPfx(password);

      const result = importPfx(pfxBuffer, password);

      expect(getStoredKey(result.keyMetadata.id)).toBeDefined();
      expect(listStoredKeys().length).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // Security invariants
  // -------------------------------------------------------------------------
  describe("Security: private key never exposed in result", () => {
    it("PFX import result must not contain private key material", () => {
      const password = "security-test";
      const { pfxBuffer } = generateTestPfx(password);

      const result = importPfx(pfxBuffer, password);
      const serialized = JSON.stringify(result);

      // Must not contain private key references
      expect(result).not.toHaveProperty("privateKey");
      expect(result.keyMetadata).not.toHaveProperty("privateKey");
      expect(result.keyMetadata).not.toHaveProperty("d");

      // The serialized form should not contain private key references
      expect(serialized).not.toContain('"privateKey"');
      expect(serialized).not.toContain('"signingKey"');
    });

    it("PEM import result must not contain private key material", () => {
      const { privatePem } = generateTestEcPem();

      const result = importPem(privatePem);
      const serialized = JSON.stringify(result);

      expect(result).not.toHaveProperty("privateKey");
      expect(result.keyMetadata).not.toHaveProperty("privateKey");
      expect(result.keyMetadata).not.toHaveProperty("d");
      expect(serialized).not.toContain('"privateKey"');
      expect(serialized).not.toContain('"signingKey"');
    });

    it("listStoredKeys should return only metadata, not KeyObjects", () => {
      const { privatePem } = generateTestEcPem();
      importPem(privatePem);

      const keys = listStoredKeys();
      const serialized = JSON.stringify(keys);

      for (const key of keys) {
        expect(key).not.toHaveProperty("privateKey");
        expect(key).not.toHaveProperty("d");
      }
      expect(serialized).not.toContain('"privateKey"');
    });
  });
});
