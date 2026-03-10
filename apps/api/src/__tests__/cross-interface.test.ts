/**
 * Cross-interface integration tests.
 *
 * Verifies that credentials built and signed using the local signing
 * pipeline (desktop / @opencred/crypto) can be verified through the
 * API /verify endpoint, and that all result codes are correctly
 * propagated across the interface boundary.
 *
 * The tests mock `verifyCredential` from @opencred/verification at
 * the API route layer (matching the existing verify.test.ts pattern),
 * but construct realistic credential payloads that mirror the exact
 * structure produced by the desktop local-signing flow:
 *
 *   CredentialBuilder (vc-core)
 *     -> signCredential (crypto/data-integrity)
 *     -> POST /verify (API)
 *     -> verifyCredential (verification)
 */

import { describe, it, expect, vi, beforeAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { Hono } from "hono";
import { CredentialBuilder } from "@opencred/vc-core";
import { signCredential } from "@opencred/crypto";
import type { SigningKey } from "@opencred/crypto";
import { deriveDidKeyId, computeKeyFingerprint } from "@opencred/did";
import { createKeyAttestationVC } from "@opencred/key-attestation";
import { createVerifyRoutes } from "../routes/verify.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

const logger = makeTestLogger();

// --- Response types ---

interface VerifyResponseBody {
  status: string;
  checks: {
    signature: { passed: boolean; detail?: string };
    expiry: { passed: boolean; detail?: string };
    revocation: { passed: boolean; detail?: string };
    dscChain?: { passed: boolean; detail?: string };
  };
}

// --- Test infrastructure ---

function createTestApp() {
  const app = new Hono();
  app.route("/verify", createVerifyRoutes());
  app.onError(errorHandler(logger));
  return app;
}

/**
 * Generate a P-256 keypair and derive the did:key verification method ID.
 * Returns a SigningKey object suitable for @opencred/crypto signCredential.
 */
function generateTestSigningKey(): SigningKey {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const vmId = deriveDidKeyId(publicKey);
  return { id: vmId, publicKey, privateKey, algorithm: "P-256" };
}

// --- Shared test key (generated once) ---

let signingKey: SigningKey;

beforeAll(() => {
  signingKey = generateTestSigningKey();
});

// =================================================================
// Cross-interface integration tests
// =================================================================

describe("Cross-interface: local-signed credential -> API /verify", () => {
  // ---------------------------------------------------------
  // 1. VALID — locally signed credential verifies via API
  // ---------------------------------------------------------
  describe("VALID: locally signed credential", () => {
    it("returns VALID for a correctly built and signed credential", async () => {
      // Build a VC using CredentialBuilder (same as desktop flow)
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({
          id: "did:example:holder123",
          name: "Jane Doe",
          degree: "BSc Computer Science",
        })
        .setValidFrom("2026-01-01T00:00:00Z")
        .setValidUntil("2030-12-31T23:59:59Z")
        .addType("UniversityDegreeCredential")
        .build();

      // Sign with the local signing pipeline (Data Integrity / ecdsa-rdfc-2019)
      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      // Ensure the signed VC has the expected proof structure
      expect(signedVC.proof).toBeDefined();
      expect(signedVC.proof.type).toBe("DataIntegrityProof");
      expect(signedVC.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
      expect(signedVC.proof.proofValue).toBeDefined();

      // Mock the verification layer to return VALID
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
          { name: "revocation", passed: true },
          { name: "attestation", passed: true, detail: "No attestation reference — not an attested credential" },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: signedVC }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("VALID");
      expect(body.checks.signature.passed).toBe(true);
      expect(body.checks.expiry.passed).toBe(true);
      expect(body.checks.revocation.passed).toBe(true);

      spy.mockRestore();
    });

    it("sends the full signed credential object to the verify endpoint", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({ id: "did:example:holder456", role: "Admin" })
        .setValidFrom("2026-03-01T00:00:00Z")
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      // Capture what verifyCredential receives to confirm the full object is passed
      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
          { name: "attestation", passed: true },
        ],
      });

      const app = createTestApp();
      await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: signedVC }),
      });

      expect(spy).toHaveBeenCalledTimes(1);
      const callArg = spy.mock.calls[0][0] as Record<string, unknown>;
      expect(callArg).toHaveProperty("proof");
      expect(callArg).toHaveProperty("@context");
      expect(callArg).toHaveProperty("credentialSubject");

      spy.mockRestore();
    });
  });

  // ---------------------------------------------------------
  // 2. EXPIRED — credential with past validUntil
  // ---------------------------------------------------------
  describe("EXPIRED: credential with past validity", () => {
    it("returns EXPIRED for a credential with validUntil in the past", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({ id: "did:example:expired-holder" })
        .setValidFrom("2020-01-01T00:00:00Z")
        .setValidUntil("2021-01-01T00:00:00Z")
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "EXPIRED",
        verified: false,
        checks: [
          { name: "signature", passed: true },
          {
            name: "date",
            passed: false,
            detail: "Credential expired (validUntil: 2021-01-01T00:00:00Z)",
          },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: signedVC }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("EXPIRED");
      expect(body.checks.signature.passed).toBe(true);
      expect(body.checks.expiry.passed).toBe(false);
      expect(body.checks.expiry.detail).toContain("expired");

      spy.mockRestore();
    });
  });

  // ---------------------------------------------------------
  // 3. Attestation chain — credential with embedded attestation
  // ---------------------------------------------------------
  describe("Attestation chain: credential with Key Attestation VC", () => {
    it("returns VALID when attestation chain is valid", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const issuerKeyJwk = signingKey.publicKey.export({ format: "jwk" });
      const keyFingerprint = computeKeyFingerprint(signingKey.publicKey);

      // Build an unsigned Key Attestation VC (simulating what the API produces)
      const attestationVC = createKeyAttestationVC({
        opencredDid: "did:key:z6OpenCredTestKey",
        issuerDid,
        issuerKeyJwk: {
          kty: issuerKeyJwk.kty as string,
          crv: issuerKeyJwk.crv,
          x: issuerKeyJwk.x,
          y: issuerKeyJwk.y,
        },
        keyFingerprint,
        keyAlgorithm: "P-256",
        verificationMethodId: signingKey.id,
        identityVerification: {
          method: "dns-txt",
          verifiedDomain: "university.example",
          verifiedAt: "2026-01-15T12:00:00Z",
          challengeId: "challenge-abc-123",
        },
        organizationName: "University of Example",
      });

      // Build the subject credential with attestation embedded in proof
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({
          id: "did:example:attested-holder",
          name: "Alice Attested",
        })
        .setValidFrom("2026-01-01T00:00:00Z")
        .setValidUntil("2030-12-31T23:59:59Z")
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      // Embed attestation VC in the proof (simulating desktop attestation embedding)
      const signedVCWithAttestation = {
        ...signedVC,
        proof: {
          ...signedVC.proof,
          keyAttestationCredential: attestationVC,
        },
      };

      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "VALID",
        verified: true,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
          { name: "attestation", passed: true },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: signedVCWithAttestation }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("VALID");
      expect(body.checks.signature.passed).toBe(true);
      expect(body.checks.expiry.passed).toBe(true);

      spy.mockRestore();
    });

    it("returns ATTESTATION_INVALID when attestation chain fails", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({ id: "did:example:bad-attestation" })
        .setValidFrom("2026-01-01T00:00:00Z")
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      // Embed a malformed attestation (wrong type, expired, etc.)
      const signedVCWithBadAttestation = {
        ...signedVC,
        proof: {
          ...signedVC.proof,
          keyAttestationCredential: {
            type: ["VerifiableCredential", "KeyAttestationCredential"],
            credentialSubject: { verificationMethodId: "did:key:zWRONG#zWRONG" },
            validFrom: "2020-01-01T00:00:00Z",
            validUntil: "2021-01-01T00:00:00Z",
          },
        },
      };

      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "ATTESTATION_INVALID",
        verified: false,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
          {
            name: "attestation",
            passed: false,
            detail: "Attestation chain invalid: Attestation had expired when credential was signed",
          },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: signedVCWithBadAttestation }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("ATTESTATION_INVALID");
      expect(body.checks.signature.passed).toBe(true);

      spy.mockRestore();
    });
  });

  // ---------------------------------------------------------
  // 4. Batch-issued credentials verify individually
  // ---------------------------------------------------------
  describe("Batch: multiple locally signed credentials verify individually", () => {
    it("verifies each batch-issued credential individually as VALID", async () => {
      const issuerDid = signingKey.id.split("#")[0];

      // Simulate batch issuance: build and sign multiple VCs
      const subjects = [
        { id: "did:example:batch-1", name: "Student A", grade: "A" },
        { id: "did:example:batch-2", name: "Student B", grade: "B+" },
        { id: "did:example:batch-3", name: "Student C", grade: "A-" },
      ];

      const signedVCs = await Promise.all(
        subjects.map(async (subject) => {
          const vc = new CredentialBuilder()
            .setIssuer(issuerDid)
            .setCredentialSubject(subject)
            .setValidFrom("2026-01-01T00:00:00Z")
            .setValidUntil("2030-12-31T23:59:59Z")
            .addType("AcademicTranscriptCredential")
            .build();
          return signCredential(vc, signingKey, {
            verificationMethod: signingKey.id,
            proofPurpose: "assertionMethod",
          });
        }),
      );

      // Ensure all VCs were signed with unique IDs
      const ids = signedVCs.map((vc) => vc.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(subjects.length);

      // Verify each credential individually via the API
      const app = createTestApp();

      for (const signedVC of signedVCs) {
        const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
        spy.mockResolvedValueOnce({
          code: "VALID",
          verified: true,
          checks: [
            { name: "signature", passed: true },
            { name: "date", passed: true },
            { name: "revocation", passed: true },
            { name: "attestation", passed: true },
          ],
        });

        const res = await app.request("/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ credential: signedVC }),
        });

        expect(res.status).toBe(200);
        const body = (await res.json()) as VerifyResponseBody;
        expect(body.status).toBe("VALID");
        expect(body.checks.signature.passed).toBe(true);

        spy.mockRestore();
      }
    });

    it("each batch credential has a distinct proof value", async () => {
      const issuerDid = signingKey.id.split("#")[0];

      const signedVCs = await Promise.all(
        [1, 2, 3].map(async (i) => {
          const vc = new CredentialBuilder()
            .setIssuer(issuerDid)
            .setCredentialSubject({ id: `did:example:batch-proof-${i}` })
            .setValidFrom("2026-01-01T00:00:00Z")
            .build();
          return signCredential(vc, signingKey, {
            verificationMethod: signingKey.id,
            proofPurpose: "assertionMethod",
          });
        }),
      );

      // All proof values must be distinct (different content => different signature)
      const proofValues = signedVCs.map((vc) => vc.proof.proofValue);
      const uniqueProofValues = new Set(proofValues);
      expect(uniqueProofValues.size).toBe(3);
    });
  });

  // ---------------------------------------------------------
  // 5. INVALID — tampered credential
  // ---------------------------------------------------------
  describe("INVALID: tampered credential", () => {
    it("returns INVALID when credential content is modified after signing", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({
          id: "did:example:tamper-target",
          degree: "BSc Computer Science",
        })
        .setValidFrom("2026-01-01T00:00:00Z")
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      // Tamper with the credential after signing
      const tamperedVC = {
        ...signedVC,
        credentialSubject: {
          ...signedVC.credentialSubject,
          degree: "PhD Quantum Computing", // Changed from BSc
        },
      };

      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "INVALID",
        verified: false,
        checks: [
          {
            name: "signature",
            passed: false,
            detail: "Signature verification failed",
          },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: tamperedVC }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("INVALID");
      expect(body.checks.signature.passed).toBe(false);
      expect(body.checks.signature.detail).toContain("Signature verification failed");

      spy.mockRestore();
    });

    it("returns INVALID when proof value is corrupted", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({ id: "did:example:corrupt-proof" })
        .setValidFrom("2026-01-01T00:00:00Z")
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      // Corrupt the proofValue
      const corruptedVC = {
        ...signedVC,
        proof: {
          ...signedVC.proof,
          proofValue: "zINVALIDPROOFVALUE123456789",
        },
      };

      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "INVALID",
        verified: false,
        checks: [
          {
            name: "signature",
            passed: false,
            detail: "Signature verification failed",
          },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: corruptedVC }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("INVALID");
      expect(body.checks.signature.passed).toBe(false);

      spy.mockRestore();
    });
  });

  // ---------------------------------------------------------
  // 6. REVOKED — credential that has been revoked
  // ---------------------------------------------------------
  describe("REVOKED: revoked credential", () => {
    it("returns REVOKED when revocation check fails", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({ id: "did:example:revoked-holder" })
        .setValidFrom("2026-01-01T00:00:00Z")
        .setCredentialStatus({
          id: "https://dedi.example/revocations/test/registry",
          type: "DeDiRevocationListStatusV1",
          statusPurpose: "revocation",
        })
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      const spy = vi.spyOn(await import("@opencred/verification"), "verifyCredential");
      spy.mockResolvedValueOnce({
        code: "REVOKED",
        verified: false,
        checks: [
          { name: "signature", passed: true },
          { name: "date", passed: true },
          {
            name: "revocation",
            passed: false,
            detail: "Credential revoked at 2026-06-15T10:00:00Z",
          },
        ],
      });

      const app = createTestApp();
      const res = await app.request("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: signedVC }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as VerifyResponseBody;
      expect(body.status).toBe("REVOKED");
      expect(body.checks.signature.passed).toBe(true);
      expect(body.checks.revocation.passed).toBe(false);
      expect(body.checks.revocation.detail).toContain("revoked");

      spy.mockRestore();
    });
  });

  // ---------------------------------------------------------
  // 7. Credential structure integrity across interfaces
  // ---------------------------------------------------------
  describe("Structure: credential maintains integrity across interfaces", () => {
    it("preserves all VC Data Model 2.0 fields through the signing pipeline", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer({ id: issuerDid, name: "Example University" })
        .setCredentialSubject({
          id: "did:example:struct-test",
          name: "Structure Test Subject",
          field1: "value1",
          field2: 42,
        })
        .setValidFrom("2026-01-01T00:00:00Z")
        .setValidUntil("2030-12-31T23:59:59Z")
        .addType("CustomTestCredential")
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      // Verify structural integrity after signing
      expect(signedVC["@context"]).toContain("https://www.w3.org/ns/credentials/v2");
      expect(signedVC.type).toContain("VerifiableCredential");
      expect(signedVC.type).toContain("CustomTestCredential");
      expect(signedVC.id).toMatch(/^urn:uuid:/);
      expect(signedVC.validFrom).toBe("2026-01-01T00:00:00Z");
      expect(signedVC.validUntil).toBe("2030-12-31T23:59:59Z");
      expect(signedVC.credentialSubject.name).toBe("Structure Test Subject");
      expect(signedVC.proof.type).toBe("DataIntegrityProof");
      expect(signedVC.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
      expect(signedVC.proof.verificationMethod).toBe(signingKey.id);
      expect(signedVC.proof.proofPurpose).toBe("assertionMethod");

      // Round-trip through JSON serialization (as happens over the wire)
      const serialized = JSON.stringify(signedVC);
      const deserialized = JSON.parse(serialized);
      expect(deserialized["@context"]).toEqual(signedVC["@context"]);
      expect(deserialized.credentialSubject).toEqual(signedVC.credentialSubject);
      expect(deserialized.proof.proofValue).toBe(signedVC.proof.proofValue);
    });

    it("proof contains all required Data Integrity fields", async () => {
      const issuerDid = signingKey.id.split("#")[0];
      const unsignedVC = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setCredentialSubject({ id: "did:example:proof-fields" })
        .setValidFrom("2026-01-01T00:00:00Z")
        .build();

      const signedVC = await signCredential(unsignedVC, signingKey, {
        verificationMethod: signingKey.id,
        proofPurpose: "assertionMethod",
      });

      const { proof } = signedVC;
      expect(proof.type).toBe("DataIntegrityProof");
      expect(proof.cryptosuite).toBe("ecdsa-rdfc-2019");
      expect(proof.created).toBeDefined();
      expect(proof.verificationMethod).toBeDefined();
      expect(proof.proofPurpose).toBe("assertionMethod");
      expect(proof.proofValue).toBeDefined();
      // Multibase base58btc encoding starts with 'z'
      expect(proof.proofValue.startsWith("z")).toBe(true);
    });
  });
});
