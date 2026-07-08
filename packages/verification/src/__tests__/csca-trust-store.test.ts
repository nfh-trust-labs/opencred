/**
 * Tests for CscaTrustStore (`packages/verification/src/csca-trust-store.ts`).
 *
 * Validates trust store loading from directories, fingerprint-based trust
 * lookups, handling of empty/missing directories, and multi-cert PEM files.
 *
 * Certificates are generated locally with node-forge — no network calls.
 */

import { describe, it, expect, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import forge from "node-forge";
import { CscaTrustStore } from "../csca-trust-store.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface TestCertBundle {
  pem: string;
  derBuffer: Buffer;
}

function generateCert(commonName: string): TestCertBundle {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 1000 * 60 * 60 * 24);
  cert.validity.notAfter = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365);

  const subject = [
    { shortName: "CN", value: commonName },
    { shortName: "O", value: "Test Org" },
    { shortName: "C", value: "US" },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: "basicConstraints", cA: true } as Record<string, unknown>,
    {
      name: "keyUsage",
      keyCertSign: true,
      digitalSignature: true,
      cRLSign: true,
    } as Record<string, unknown>,
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const pem = forge.pki.certificateToPem(cert);
  // Convert PEM to DER buffer
  const derAsn1 = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
  const derBuffer = Buffer.from(derAsn1.getBytes(), "binary");

  return { pem, derBuffer };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("CscaTrustStore", () => {
  describe("fromDirectory", () => {
    it("loads PEM files from a directory with correct size", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        const cert1 = generateCert("Root CA 1");
        const cert2 = generateCert("Root CA 2");
        await writeFile(path.join(dir, "root1.pem"), cert1.pem);
        await writeFile(path.join(dir, "root2.crt"), cert2.pem);
        await writeFile(path.join(dir, "ignored.txt"), "not a cert");

        const store = await CscaTrustStore.fromDirectory(dir);
        expect(store.size).toBe(2);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("loads DER-encoded certificates", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        const cert = generateCert("DER Root");
        await writeFile(path.join(dir, "root.der"), cert.derBuffer);

        const store = await CscaTrustStore.fromDirectory(dir);
        expect(store.size).toBe(1);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("handles PEM files with multiple concatenated certificates", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        const cert1 = generateCert("Multi Root 1");
        const cert2 = generateCert("Multi Root 2");
        const bundledPem = cert1.pem + "\n" + cert2.pem;
        await writeFile(path.join(dir, "bundle.pem"), bundledPem);

        const store = await CscaTrustStore.fromDirectory(dir);
        expect(store.size).toBe(2);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("returns empty store for non-existent directory with warning", async () => {
      const onWarning = vi.fn();
      const store = await CscaTrustStore.fromDirectory(
        path.join(tmpdir(), "definitely-does-not-exist-csca-12345"),
        { onWarning },
      );
      expect(store.size).toBe(0);
      expect(onWarning).toHaveBeenCalledTimes(1);
      expect(onWarning.mock.calls[0][0]).toContain("not found or unreadable");
    });

    it("returns empty store for empty directory with warning", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        const onWarning = vi.fn();
        const store = await CscaTrustStore.fromDirectory(dir, { onWarning });
        expect(store.size).toBe(0);
        expect(onWarning).toHaveBeenCalledTimes(1);
        expect(onWarning.mock.calls[0][0]).toContain("empty");
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("warns about files with no PEM certificate blocks", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        await writeFile(path.join(dir, "bad.pem"), "not a real PEM file\n");
        const cert = generateCert("Good Root");
        await writeFile(path.join(dir, "good.pem"), cert.pem);

        const onWarning = vi.fn();
        const store = await CscaTrustStore.fromDirectory(dir, { onWarning });
        expect(store.size).toBe(1);
        // One warning for the bad file, plus the good file loads fine
        const badFileWarning = onWarning.mock.calls.find(
          (call: string[]) =>
            typeof call[0] === "string" && call[0].includes("No PEM certificate blocks"),
        );
        expect(badFileWarning).toBeDefined();
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("silently ignores non-certificate file extensions", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        const cert = generateCert("Root");
        await writeFile(path.join(dir, "root.pem"), cert.pem);
        await writeFile(path.join(dir, "README.md"), "# Notes\n");
        await writeFile(path.join(dir, "config.json"), "{}");

        const onWarning = vi.fn();
        const store = await CscaTrustStore.fromDirectory(dir, { onWarning });
        expect(store.size).toBe(1);
        // No warnings for non-candidate files (README.md, config.json)
        expect(onWarning).not.toHaveBeenCalled();
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
  });

  describe("isTrusted", () => {
    it("returns true for a certificate that IS in the store", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        const cert = generateCert("Trusted Root");
        await writeFile(path.join(dir, "root.pem"), cert.pem);

        const store = await CscaTrustStore.fromDirectory(dir);
        const x509 = new X509Certificate(cert.pem);
        expect(store.isTrusted(x509)).toBe(true);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("returns false for a certificate NOT in the store", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        const trustedCert = generateCert("Trusted Root");
        const untrustedCert = generateCert("Untrusted Root");
        await writeFile(path.join(dir, "root.pem"), trustedCert.pem);

        const store = await CscaTrustStore.fromDirectory(dir);
        const x509 = new X509Certificate(untrustedCert.pem);
        expect(store.isTrusted(x509)).toBe(false);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("returns false on an empty trust store", () => {
      const store = CscaTrustStore.empty();
      const cert = generateCert("Any Root");
      const x509 = new X509Certificate(cert.pem);
      expect(store.isTrusted(x509)).toBe(false);
    });
  });

  describe("empty", () => {
    it("creates a store with size 0", () => {
      const store = CscaTrustStore.empty();
      expect(store.size).toBe(0);
    });
  });

  describe("toPemArray", () => {
    it("returns PEM strings for all loaded certificates", async () => {
      const dir = await mkdtemp(path.join(tmpdir(), "csca-class-test-"));
      try {
        const cert1 = generateCert("PEM Array Root 1");
        const cert2 = generateCert("PEM Array Root 2");
        await writeFile(path.join(dir, "root1.pem"), cert1.pem);
        await writeFile(path.join(dir, "root2.pem"), cert2.pem);

        const store = await CscaTrustStore.fromDirectory(dir);
        const pems = store.toPemArray();
        expect(pems).toHaveLength(2);
        // Each PEM should be a valid certificate
        for (const pem of pems) {
          expect(() => new X509Certificate(pem)).not.toThrow();
        }
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });

    it("returns empty array for an empty store", () => {
      const store = CscaTrustStore.empty();
      expect(store.toPemArray()).toEqual([]);
    });
  });
});
