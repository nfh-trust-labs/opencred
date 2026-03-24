/**
 * Attestation challenge and verification endpoints.
 *
 * POST /attestation/challenge          — request a domain verification challenge
 * POST /attestation/challenge/:id/verify — verify domain ownership and receive Key Attestation VC
 * POST /attestation/attest-by-vc       — submit a business VC for attestation
 *
 * SECURITY INVARIANTS:
 *  - Signing uses the server's loaded key — never from request bodies.
 *  - Key material is NEVER logged or returned in responses.
 *  - Challenge tokens use CSPRNG (via @opencred/domain-verification).
 *  - Challenges are single-use — deleted after verification.
 */

import { Hono } from "hono";
import { z } from "zod";
import { randomBytes } from "node:crypto";
import {
  ChallengeStore,
  verifyDomainOwnership,
  DNS_TXT_PREFIX,
  WELL_KNOWN_PATH,
} from "@opencred/domain-verification";
import { createKeyAttestationVC } from "@opencred/key-attestation";
import type { IdentityVerificationMethod } from "@opencred/key-attestation";
import {
  prepareVcJwtProof,
  completeVcJwtProof,
} from "@opencred/crypto";
import { verifyBusinessVc } from "@opencred/verification";
import { requireSigner } from "../signing/key-manager.js";

const attestation = new Hono();

// Singleton challenge store (in-memory with TTL-based expiry)
const challengeStore = new ChallengeStore();

// --- Request schemas ---

const challengeRequestSchema = z.object({
  domain: z.string().min(1),
  method: z.enum(["dns-txt", "http"]),
});

const verifyRequestSchema = z.object({
  publicKeyJwk: z.object({ kty: z.string() }).passthrough(),
  issuerDid: z.string().startsWith("did:"),
  keyFingerprint: z.string().min(1),
  keyAlgorithm: z.string().min(1),
  verificationMethodId: z.string().min(1),
  organizationName: z.string().min(1),
});

const attestByVcRequestSchema = z.object({
  businessVc: z.union([z.string(), z.record(z.unknown())]),
  publicKeyJwk: z.object({ kty: z.string() }).passthrough(),
  issuerDid: z.string().startsWith("did:"),
  keyFingerprint: z.string().min(1),
  keyAlgorithm: z.string().min(1),
  verificationMethodId: z.string().min(1),
});

// --- Helpers ---

/**
 * Build and sign a Key Attestation VC using the server's loaded key.
 */
async function buildAndSignAttestation(params: {
  issuerDid: string;
  publicKeyJwk: Record<string, unknown>;
  keyFingerprint: string;
  keyAlgorithm: string;
  verificationMethodId: string;
  organizationName: string;
  domain: string;
  method: IdentityVerificationMethod;
  sourceCredentialId?: string;
}): Promise<Record<string, unknown>> {
  const signer = requireSigner();

  const unsigned = createKeyAttestationVC({
    opencredDid: signer.id,
    issuerDid: params.issuerDid,
    issuerKeyJwk: params.publicKeyJwk as { kty: string; [key: string]: unknown },
    keyFingerprint: params.keyFingerprint,
    keyAlgorithm: params.keyAlgorithm,
    verificationMethodId: params.verificationMethodId,
    identityVerification: {
      method: params.method,
      verifiedDomain: params.domain,
      verifiedAt: new Date().toISOString(),
      sourceCredentialId: params.sourceCredentialId,
    },
    organizationName: params.organizationName,
  });

  // Sign with VC-JWT (same pattern as credentials.ts)
  const vcAsRecord = unsigned as unknown as Record<string, unknown>;
  const { signingInput } = prepareVcJwtProof(vcAsRecord, signer.algorithm, {
    verificationMethod: signer.id,
  });
  const dataToSign = new TextEncoder().encode(signingInput);
  const signatureBytes = await signer.sign(dataToSign);
  const jwt = completeVcJwtProof(signingInput, signatureBytes);

  return {
    ...unsigned,
    proof: { type: "JsonWebSignature2020", jwt },
  };
}

// --- Endpoints ---

/**
 * POST /attestation/challenge
 *
 * Create a domain verification challenge (DNS TXT or HTTP).
 */
attestation.post("/attestation/challenge", async (c) => {
  const body = await c.req.json();
  const parsed = challengeRequestSchema.parse(body);

  // Generate a CSPRNG token (256-bit entropy) and store via ChallengeStore.
  const token = randomBytes(32).toString("hex");
  const stored = challengeStore.create(parsed.domain, parsed.method, token);

  const instructions = parsed.method === "dns-txt"
    ? `Add a DNS TXT record to ${parsed.domain} with value: ${DNS_TXT_PREFIX}${token}`
    : `Place the token at https://${parsed.domain}/${WELL_KNOWN_PATH}/${stored.id}`;

  return c.json({
    challengeId: stored.id,
    token,
    instructions,
    expiresAt: stored.expiresAt.toISOString(),
  });
});

/**
 * POST /attestation/challenge/:id/verify
 *
 * Verify domain ownership via a previously created challenge,
 * then build and sign a Key Attestation VC.
 */
attestation.post("/attestation/challenge/:id/verify", async (c) => {
  const challengeId = c.req.param("id");

  // ChallengeStore.get() returns undefined for expired or missing challenges
  const challenge = challengeStore.get(challengeId);
  if (!challenge) {
    return c.json(
      { error: { code: "NOT_FOUND", message: "Challenge not found or expired" } },
      404,
    );
  }

  const body = await c.req.json();
  const parsed = verifyRequestSchema.parse(body);

  // Verify domain ownership
  const result = await verifyDomainOwnership(challengeId, challengeStore);

  if (!result.verified) {
    return c.json(
      { error: { code: "VERIFICATION_FAILED", message: result.error ?? "Domain verification failed" } },
      400,
    );
  }

  // Delete challenge (single-use)
  challengeStore.delete(challengeId);

  // Build and sign attestation VC
  const credential = await buildAndSignAttestation({
    issuerDid: parsed.issuerDid,
    publicKeyJwk: parsed.publicKeyJwk as Record<string, unknown>,
    keyFingerprint: parsed.keyFingerprint,
    keyAlgorithm: parsed.keyAlgorithm,
    verificationMethodId: parsed.verificationMethodId,
    organizationName: parsed.organizationName,
    domain: challenge.domain,
    method: challenge.method as IdentityVerificationMethod,
  });

  return c.json({ credential });
});

/**
 * POST /attestation/attest-by-vc
 *
 * Alternative attestation path: submit a verified business VC
 * instead of a domain challenge. OpenCred verifies the VC,
 * extracts identity, and signs a Key Attestation VC.
 */
attestation.post("/attestation/attest-by-vc", async (c) => {
  const body = await c.req.json();
  const parsed = attestByVcRequestSchema.parse(body);

  // Verify the business VC
  const verification = await verifyBusinessVc(parsed.businessVc);

  if (!verification.verification.verified) {
    const failedCheck = verification.verification.checks.find((ch) => !ch.passed);
    const detail = failedCheck?.detail ?? "unknown error";
    return c.json(
      {
        error: {
          code: "BUSINESS_VC_INVALID",
          message: `Business VC verification failed: ${detail}`,
        },
      },
      400,
    );
  }

  if (!verification.identity) {
    return c.json(
      { error: { code: "IDENTITY_EXTRACTION_FAILED", message: "Could not extract identity from business VC" } },
      400,
    );
  }

  const organizationName = verification.identity.organizationName;
  if (!organizationName) {
    return c.json(
      { error: { code: "IDENTITY_EXTRACTION_FAILED", message: "Business VC does not contain an organization name" } },
      400,
    );
  }
  const domain = verification.identity.subjectId ?? organizationName;

  // Extract a credential ID for audit trail
  let sourceCredentialId: string | undefined;
  if (typeof parsed.businessVc === "object") {
    sourceCredentialId = (parsed.businessVc as Record<string, unknown>).id as string | undefined;
  }

  const credential = await buildAndSignAttestation({
    issuerDid: parsed.issuerDid,
    publicKeyJwk: parsed.publicKeyJwk as Record<string, unknown>,
    keyFingerprint: parsed.keyFingerprint,
    keyAlgorithm: parsed.keyAlgorithm,
    verificationMethodId: parsed.verificationMethodId,
    organizationName,
    domain,
    method: "business-vc",
    sourceCredentialId,
  });

  return c.json({ credential });
});

export { attestation };
