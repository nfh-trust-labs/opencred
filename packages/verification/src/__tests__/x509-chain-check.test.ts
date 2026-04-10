/**
 * Tests for the X.509 chain check (`packages/verification/src/x509-chain-check.ts`).
 *
 * Regression coverage for nfh-trust-labs/opencred#316:
 *  - the chain check must NOT silently pass when DID resolution fails;
 *  - the chain check must NOT silently pass when no trust anchor is configured;
 *  - the chain check must verify that the chain terminates at a configured
 *    trust anchor before reporting `passed`.
 *
 * Self-signed and CA-signed certificates are generated locally with
 * node-forge so that no remote network calls are needed.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import forge from "node-forge";
import type {
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
  JWK,
} from "@opencred/did";
import { checkX509Chain, loadCscaTrustStore } from "../x509-chain-check.js";
import { CscaTrustStore } from "../csca-trust-store.js";

// ---------------------------------------------------------------------------
// Test cert helpers
// ---------------------------------------------------------------------------

interface TestCertBundle {
  pem: string;
  derBase64: string; // base64 of the DER body — what x5c carries
  forgeKeys: forge.pki.rsa.KeyPair;
  jwk: JWK;
}

interface CertOptions {
  commonName: string;
  isCa?: boolean;
  notBefore?: Date;
  notAfter?: Date;
  serial?: string;
}

/**
 * Generate an RSA key pair plus a self-signed (or issuer-signed) certificate.
 * Returns a bundle containing the PEM, the base64 DER form (for x5c), the
 * forge KeyPair, and a JWK derived from the public key.
 */
function generateCert(
  opts: CertOptions,
  issuer?: { keys: forge.pki.rsa.KeyPair; cert: forge.pki.Certificate; commonName: string },
): TestCertBundle {
  const forgeKeys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forgeKeys.publicKey;
  cert.serialNumber = opts.serial ?? "01";
  cert.validity.notBefore = opts.notBefore ?? new Date(Date.now() - 1000 * 60 * 60 * 24);
  cert.validity.notAfter = opts.notAfter ?? new Date(Date.now() + 1000 * 60 * 60 * 24 * 365);

  const subject = [
    { shortName: "CN", value: opts.commonName },
    { shortName: "O", value: "Test Org" },
    { shortName: "C", value: "US" },
  ];
  cert.setSubject(subject);
  cert.setIssuer(
    issuer
      ? [
          { shortName: "CN", value: issuer.commonName },
          { shortName: "O", value: "Test Org" },
          { shortName: "C", value: "US" },
        ]
      : subject,
  );

  // For self-signed certs, set up basic extensions to look like a CA root.
  // node-forge's @types declares extensions as `any[]`, so we use a loose
  // record type to keep the test compiling under strict TS.
  const extensions: Array<Record<string, unknown>> = [];
  if (opts.isCa) {
    extensions.push({ name: "basicConstraints", cA: true });
    extensions.push({
      name: "keyUsage",
      keyCertSign: true,
      digitalSignature: true,
      cRLSign: true,
    });
  } else {
    extensions.push({ name: "basicConstraints", cA: false });
    extensions.push({
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
    });
  }
  cert.setExtensions(extensions);

  // Sign with the issuer's key (or self-sign if no issuer was given).
  const signingKey = issuer?.keys.privateKey ?? forgeKeys.privateKey;
  cert.sign(signingKey, forge.md.sha256.create());

  const pem = forge.pki.certificateToPem(cert);
  const x509 = new X509Certificate(pem);
  const jwk = x509.publicKey.export({ format: "jwk" }) as JWK;

  // Strip PEM headers/footers and whitespace to get the base64 DER body.
  const derBase64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s+/g, "");

  return { pem, derBase64, forgeKeys, jwk };
}

interface ChainBundle {
  rootPem: string;
  intermediatePem: string;
  leafPem: string;
  rootBase64: string;
  intermediateBase64: string;
  leafBase64: string;
  leafJwk: JWK;
}

/**
 * Build a 3-cert chain: leaf <- intermediate <- root.
 * Returns the PEMs, base64-DER strings, and the leaf's JWK.
 */
function buildCertChain(): ChainBundle {
  const root = generateCert({ commonName: "Test Root CA", isCa: true });
  const rootForgeCert = forge.pki.certificateFromPem(root.pem);

  const intermediate = generateCert(
    { commonName: "Test Intermediate CA", isCa: true, serial: "02" },
    { keys: root.forgeKeys, cert: rootForgeCert, commonName: "Test Root CA" },
  );
  const intermediateForgeCert = forge.pki.certificateFromPem(intermediate.pem);

  const leaf = generateCert(
    { commonName: "Test DSC Leaf", serial: "03" },
    {
      keys: intermediate.forgeKeys,
      cert: intermediateForgeCert,
      commonName: "Test Intermediate CA",
    },
  );

  return {
    rootPem: root.pem,
    intermediatePem: intermediate.pem,
    leafPem: leaf.pem,
    rootBase64: root.derBase64,
    intermediateBase64: intermediate.derBase64,
    leafBase64: leaf.derBase64,
    leafJwk: leaf.jwk,
  };
}

/**
 * Build a self-signed (single-cert) chain. The "trust anchor" is the cert
 * itself; an attacker presents this when they don't have a real DSC.
 */
function buildSelfSignedChain(): { pem: string; derBase64: string; jwk: JWK } {
  const cert = generateCert({ commonName: "Attacker Self-Signed" });
  return { pem: cert.pem, derBase64: cert.derBase64, jwk: cert.jwk };
}

/**
 * Helper that constructs a minimal credential dictionary with the supplied
 * proof.x5c and proof.verificationMethod.
 */
function buildCredential(args: {
  x5c?: string[];
  verificationMethod?: string;
  created?: string;
}): Record<string, unknown> {
  const proof: Record<string, unknown> = {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: args.created ?? new Date().toISOString(),
  };
  if (args.x5c) proof["x5c"] = args.x5c;
  if (args.verificationMethod !== undefined) {
    proof["verificationMethod"] = args.verificationMethod;
  }
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:test-cred",
    type: ["VerifiableCredential"],
    issuer: "did:web:test.example",
    credentialSubject: { id: "did:example:holder" },
    proof,
  };
}

/**
 * Build a DID resolver that returns a single VM with the supplied JWK.
 */
function makeResolver(did: string, vmId: string, jwk: JWK): DIDResolver {
  const verificationMethod: VerificationMethod = {
    id: vmId,
    type: "JsonWebKey",
    controller: did,
    publicKeyJwk: jwk,
  };
  return {
    resolve: async (input: string): Promise<DIDResolutionResult> => {
      if (input !== did) {
        return {
          didDocument: null,
          didResolutionMetadata: { error: "notFound" },
          didDocumentMetadata: {},
        };
      }
      return {
        didDocument: {
          "@context": "https://www.w3.org/ns/did/v1",
          id: did,
          verificationMethod: [verificationMethod],
          assertionMethod: [vmId],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

const failingResolver: DIDResolver = {
  resolve: async (): Promise<DIDResolutionResult> => ({
    didDocument: null,
    didResolutionMetadata: { error: "notFound" },
    didDocumentMetadata: {},
  }),
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("checkX509Chain", () => {
  it("passes through credentials without an x5c chain", async () => {
    const credential = buildCredential({
      verificationMethod: "did:web:test.example#key-0",
    });
    const result = await checkX509Chain(credential);
    expect(result.passed).toBe(true);
    expect(result.detail).toContain("not a DSC-backed credential");
  });

  it("passes through credentials with no proof", async () => {
    const result = await checkX509Chain({ "@context": [] });
    expect(result.passed).toBe(true);
  });

  describe("#316 — fail closed when trust is incomplete", () => {
    it("fails when an x5c chain is present but no trust anchors are configured", async () => {
      const chain = buildCertChain();
      const did = "did:web:test.example";
      const vmId = `${did}#key-0`;
      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, chain.leafJwk),
        // trustAnchors deliberately omitted.
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("requires a configured trust anchor");
    });

    it("fails when DID resolution returns nothing — does NOT silently skip", async () => {
      const chain = buildCertChain();
      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
        verificationMethod: "did:web:test.example#key-0",
      });

      const result = await checkX509Chain(credential, {
        didResolver: failingResolver,
        trustAnchors: [chain.rootPem],
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Unable to confirm");
    });

    it("fails when verificationMethod is missing", async () => {
      const chain = buildCertChain();
      const credential = buildCredential({
        x5c: [chain.leafBase64],
      });
      // Strip verificationMethod from the proof.
      const proof = credential["proof"] as Record<string, unknown>;
      delete proof["verificationMethod"];

      const result = await checkX509Chain(credential, {
        trustAnchors: [chain.rootPem],
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("no proof.verificationMethod");
    });

    it("fails for a self-signed chain that does not chain to the trust anchor", async () => {
      // Attacker presents a self-signed certificate. They control the DID
      // document so the leaf key matches the resolved VM, but the cert is
      // not signed by any configured trust anchor.
      const attacker = buildSelfSignedChain();
      const real = buildCertChain();
      const did = "did:web:attacker.example";
      const vmId = `${did}#key-0`;

      const credential = buildCredential({
        x5c: [attacker.derBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, attacker.jwk),
        // Trust anchor is unrelated to the attacker's self-signed cert.
        trustAnchors: [real.rootPem],
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("does not terminate at a configured trust anchor");
    });

    it("fails for a self-signed chain even when DID resolves correctly and no anchors configured", async () => {
      // Combined #311 + #316 attack scenario: forged credential with a
      // self-signed x5c chain. With no trust anchors configured the
      // pre-fix code returned `code: VALID`. The fix MUST return INVALID.
      const attacker = buildSelfSignedChain();
      const did = "did:web:attacker.example";
      const vmId = `${did}#key-0`;

      const credential = buildCredential({
        x5c: [attacker.derBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, attacker.jwk),
        trustAnchors: [], // empty list — fail closed
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("requires a configured trust anchor");
    });
  });

  describe("happy path — valid chain", () => {
    it("passes for a valid 3-cert chain anchored to a trusted root", async () => {
      const chain = buildCertChain();
      const did = "did:web:test.example";
      const vmId = `${did}#key-0`;

      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, chain.leafJwk),
        trustAnchors: [chain.rootPem],
      });

      expect(result.passed).toBe(true);
      expect(result.detail).toContain("DSC verified");
      expect(result.detail).toContain("anchored to");
    });

    it("passes when the trust anchor is referenced by signature only (root not in x5c)", async () => {
      // x5c contains [leaf, intermediate]; the root is supplied as the
      // trust anchor. The intermediate must verify against the root.
      const chain = buildCertChain();
      const did = "did:web:test.example";
      const vmId = `${did}#key-0`;

      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, chain.leafJwk),
        trustAnchors: [chain.rootPem],
      });

      expect(result.passed).toBe(true);
    });

    it("rejects a valid chain whose leaf key does not match the resolved DID", async () => {
      const chain = buildCertChain();
      const wrong = buildSelfSignedChain();
      const did = "did:web:test.example";
      const vmId = `${did}#key-0`;

      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, wrong.jwk),
        trustAnchors: [chain.rootPem],
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("does not match");
    });

    it("rejects an expired chain at proof.created time", async () => {
      const chain = buildCertChain();
      const did = "did:web:test.example";
      const vmId = `${did}#key-0`;

      // Set proof.created far in the future, after every cert has expired.
      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
        verificationMethod: vmId,
        created: "2099-01-01T00:00:00Z",
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, chain.leafJwk),
        trustAnchors: [chain.rootPem],
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("expired");
    });
  });

  describe("trust anchor parsing", () => {
    it("rejects malformed PEM trust anchors with a clear error", async () => {
      const chain = buildCertChain();
      const did = "did:web:test.example";
      const vmId = `${did}#key-0`;

      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, chain.leafJwk),
        trustAnchors: ["not a real PEM"],
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("Failed to parse configured trust anchors");
    });
  });
});

// ---------------------------------------------------------------------------
// loadCscaTrustStore
// ---------------------------------------------------------------------------

describe("loadCscaTrustStore", () => {
  it("loads PEM files from a directory", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "csca-test-"));
    try {
      const root = generateCert({ commonName: "Loaded Root", isCa: true });
      await writeFile(path.join(dir, "root1.pem"), root.pem);
      await writeFile(path.join(dir, "root2.crt"), root.pem);
      await writeFile(path.join(dir, "ignored.txt"), "ignored");

      const anchors = await loadCscaTrustStore(dir);
      expect(anchors.length).toBe(2);
      // Each anchor must parse as a real X.509 cert.
      for (const pem of anchors) {
        expect(() => new X509Certificate(pem)).not.toThrow();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("returns an empty array for a missing directory", async () => {
    const result = await loadCscaTrustStore(path.join(tmpdir(), "definitely-not-there-12345"));
    expect(result).toEqual([]);
  });

  it("splits files containing multiple concatenated certificates", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "csca-test-"));
    try {
      const root1 = generateCert({ commonName: "Multi Root 1", isCa: true });
      const root2 = generateCert({ commonName: "Multi Root 2", isCa: true });
      await writeFile(path.join(dir, "bundle.pem"), root1.pem + "\n" + root2.pem);

      const anchors = await loadCscaTrustStore(dir);
      expect(anchors.length).toBe(2);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("calls onSkipped when the directory does not exist", async () => {
    const missing = path.join(tmpdir(), "definitely-not-there-67890");
    const skipped: Array<{ path: string; reason: string }> = [];
    const result = await loadCscaTrustStore(missing, {
      onSkipped: (info) => skipped.push(info),
    });
    expect(result).toEqual([]);
    expect(skipped).toHaveLength(1);
    expect(skipped[0].path).toBe(missing);
    expect(skipped[0].reason).toContain("unable to read trust store directory");
  });

  it("calls onSkipped for files with no PEM certificate blocks", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "csca-test-"));
    try {
      await writeFile(path.join(dir, "corrupt.pem"), "not actually a PEM file\n");
      const root = generateCert({ commonName: "Good Root", isCa: true });
      await writeFile(path.join(dir, "good.pem"), root.pem);

      const skipped: Array<{ path: string; reason: string }> = [];
      const anchors = await loadCscaTrustStore(dir, {
        onSkipped: (info) => skipped.push(info),
      });

      // Good cert still loaded.
      expect(anchors).toHaveLength(1);
      // Corrupt file surfaced to caller.
      expect(skipped).toHaveLength(1);
      expect(skipped[0].path).toContain("corrupt.pem");
      expect(skipped[0].reason).toContain("no PEM certificate blocks");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not call onSkipped for non-candidate file extensions", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "csca-test-"));
    try {
      const root = generateCert({ commonName: "Root", isCa: true });
      await writeFile(path.join(dir, "root.pem"), root.pem);
      // README.md has a non-candidate extension and should be ignored silently.
      await writeFile(path.join(dir, "README.md"), "# Trust store notes\n");

      const skipped: Array<{ path: string; reason: string }> = [];
      const anchors = await loadCscaTrustStore(dir, {
        onSkipped: (info) => skipped.push(info),
      });

      expect(anchors).toHaveLength(1);
      expect(skipped).toHaveLength(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not call onSkipped on the happy path", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "csca-test-"));
    try {
      const root = generateCert({ commonName: "Happy Root", isCa: true });
      await writeFile(path.join(dir, "root.pem"), root.pem);

      const skipped: Array<{ path: string; reason: string }> = [];
      const anchors = await loadCscaTrustStore(dir, {
        onSkipped: (info) => skipped.push(info),
      });

      expect(anchors).toHaveLength(1);
      expect(skipped).toHaveLength(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// CscaTrustStore integration with checkX509Chain
// ---------------------------------------------------------------------------

describe("CscaTrustStore + checkX509Chain integration", () => {
  it("passes when trust store loaded from directory contains the root cert", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "csca-integration-"));
    try {
      const chain = buildCertChain();
      // Write the root cert to the trust store directory.
      await writeFile(path.join(dir, "root.pem"), chain.rootPem);

      const trustStore = await CscaTrustStore.fromDirectory(dir);
      expect(trustStore.size).toBe(1);

      const did = "did:web:test.example";
      const vmId = `${did}#key-0`;
      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, chain.leafJwk),
        trustAnchors: trustStore.toPemArray(),
      });

      expect(result.passed).toBe(true);
      expect(result.detail).toContain("DSC verified");
      expect(result.detail).toContain("anchored to");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("fails when trust store does not contain the chain's root cert", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "csca-integration-"));
    try {
      // Load a different root cert into the trust store — NOT the one
      // that signed the chain.
      const unrelated = generateCert({ commonName: "Unrelated CSCA", isCa: true });
      await writeFile(path.join(dir, "unrelated.pem"), unrelated.pem);

      const trustStore = await CscaTrustStore.fromDirectory(dir);
      expect(trustStore.size).toBe(1);

      const chain = buildCertChain();
      const did = "did:web:test.example";
      const vmId = `${did}#key-0`;
      const credential = buildCredential({
        x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
        verificationMethod: vmId,
      });

      const result = await checkX509Chain(credential, {
        didResolver: makeResolver(did, vmId, chain.leafJwk),
        trustAnchors: trustStore.toPemArray(),
      });

      expect(result.passed).toBe(false);
      expect(result.detail).toContain("does not terminate at a configured trust anchor");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("fails closed when CscaTrustStore is empty (no graceful skip for DSC creds)", async () => {
    const trustStore = CscaTrustStore.empty();
    expect(trustStore.size).toBe(0);

    const chain = buildCertChain();
    const did = "did:web:test.example";
    const vmId = `${did}#key-0`;
    const credential = buildCredential({
      x5c: [chain.leafBase64, chain.intermediateBase64, chain.rootBase64],
      verificationMethod: vmId,
    });

    const result = await checkX509Chain(credential, {
      didResolver: makeResolver(did, vmId, chain.leafJwk),
      trustAnchors: trustStore.toPemArray(),
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("requires a configured trust anchor");
  });

  it("non-DSC credentials pass without a trust store (graceful degradation)", async () => {
    // Credentials without an x5c chain (e.g. did:web self-published keys)
    // do not require trust anchors and should pass the x509-chain check.
    const credential = buildCredential({
      verificationMethod: "did:web:test.example#key-0",
    });

    const result = await checkX509Chain(credential);
    expect(result.passed).toBe(true);
    expect(result.detail).toContain("not a DSC-backed credential");
  });

  it("isTrusted correctly identifies root cert loaded from directory", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "csca-integration-"));
    try {
      const chain = buildCertChain();
      await writeFile(path.join(dir, "root.pem"), chain.rootPem);

      const trustStore = await CscaTrustStore.fromDirectory(dir);
      const rootX509 = new X509Certificate(chain.rootPem);

      expect(trustStore.isTrusted(rootX509)).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
