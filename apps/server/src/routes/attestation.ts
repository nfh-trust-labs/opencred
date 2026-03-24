/**
 * Attestation endpoints — domain verification and business VC attestation.
 *
 * POST /attestation/challenge          — create a domain verification challenge
 * POST /attestation/challenge/:id/verify — verify domain + issue Key Attestation VC
 * POST /attestation/attest-by-vc       — attest via business VC
 *
 * All attestation endpoints are PUBLIC (no Bearer auth required).
 *
 * SECURITY INVARIANTS:
 *  - Key material is NEVER logged or returned in error responses.
 *  - All tokens are generated with CSPRNG (crypto.randomBytes via domain-verification).
 *  - Error responses use the OpenCredError hierarchy for sanitization.
 *  - JSON-LD contexts are bundled — no remote fetch.
 */

import { Hono } from "hono";
import { z } from "zod";
import {
  ChallengeStore,
  generateChallenge,
  verifyDomainOwnership,
} from "@opencred/domain-verification";
import { createKeyAttestationVC } from "@opencred/key-attestation";
import type { IdentityVerificationMethod } from "@opencred/key-attestation";
import {
  prepareVcJwtProof,
  completeVcJwtProof,
} from "@opencred/crypto";
import { verifyBusinessVc } from "@opencred/verification";
import {
  AttestationError,
  ValidationError,
} from "@opencred/shared";
import { requireSigner } from "../signing/key-manager.js";
import { getLogger } from "../logger.js";

const attestation = new Hono();

// Shared challenge store (in-memory, 24-hour TTL managed by ChallengeStore)
const challengeStore = new ChallengeStore();

// ─── Request Schemas ──────────────────────────────────────────────────

const createChallengeSchema = z.object({
  domain: z.string().min(1, "domain is required"),
  method: z.enum(["dns-txt", "http"], {
    errorMap: () => ({ message: "method must be 'dns-txt' or 'http'" }),
  }),
});

const verifyChallengeSchema = z.object({
  publicKeyJwk: z.object({ kty: z.string() }).passthrough(),
  issuerDid: z.string().min(1, "issuerDid is required"),
  keyFingerprint: z.string().min(1, "keyFingerprint is required"),
  keyAlgorithm: z.string().min(1, "keyAlgorithm is required"),
  verificationMethodId: z.string().min(1, "verificationMethodId is required"),
  organizationName: z.string().min(1, "organizationName is required"),
});

const attestByVcSchema = z.object({
  businessVc: z.union([z.string(), z.object({}).passthrough()]),
  publicKeyJwk: z.object({ kty: z.string() }).passthrough(),
  issuerDid: z.string().min(1, "issuerDid is required"),
  keyFingerprint: z.string().min(1, "keyFingerprint is required"),
  keyAlgorithm: z.string().min(1, "keyAlgorithm is required"),
  verificationMethodId: z.string().min(1, "verificationMethodId is required"),
});

// ─── POST /attestation/challenge ──────────────────────────────────────

attestation.post("/attestation/challenge", async (c) => {
  const body = await c.req.json();
  const parsed = createChallengeSchema.parse(body);
  const logger = getLogger();

  // Generate challenge via domain-verification package (CSPRNG tokens)
  const details = generateChallenge(parsed.domain, parsed.method);

  // Store the challenge for later verification
  const stored = challengeStore.create(
    details.domain,
    parsed.method,
    details.token,
  );

  logger.info(
    { challengeId: stored.id, domain: parsed.domain, method: parsed.method },
    "Domain verification challenge created",
  );

  return c.json({
    challengeId: stored.id,
    token: details.token,
    instructions: details.instructions,
    expiresAt: stored.expiresAt.toISOString(),
  });
});

// ─── POST /attestation/challenge/:id/verify ───────────────────────────

attestation.post("/attestation/challenge/:id/verify", async (c) => {
  const challengeId = c.req.param("id");
  const body = await c.req.json();
  const parsed = verifyChallengeSchema.parse(body);
  const logger = getLogger();

  // Check if the challenge exists before attempting verification
  const challenge = challengeStore.get(challengeId);
  if (!challenge) {
    // Distinguish between "never existed" and "expired"
    return c.json(
      { error: { code: "NOT_FOUND", message: "Challenge not found or expired" } },
      404,
    );
  }

  // Verify domain ownership (dispatches to DNS or HTTP verifier)
  const result = await verifyDomainOwnership(challengeId, challengeStore);

  if (!result.verified) {
    const statusCode = result.error?.includes("expired") ? 410 : 400;
    return c.json(
      { error: { code: "VERIFICATION_FAILED", message: result.error ?? "Domain verification failed" } },
      statusCode,
    );
  }

  // Map domain-verification method to IdentityVerificationMethod
  const method: IdentityVerificationMethod = challenge.method === "http" ? "http-challenge" : "dns-txt";

  // Build unsigned Key Attestation VC
  const signer = requireSigner();
  const unsignedVc = createKeyAttestationVC({
    opencredDid: signer.id,
    issuerDid: parsed.issuerDid,
    issuerKeyJwk: parsed.publicKeyJwk,
    keyFingerprint: parsed.keyFingerprint,
    keyAlgorithm: parsed.keyAlgorithm,
    verificationMethodId: parsed.verificationMethodId,
    identityVerification: {
      method,
      verifiedDomain: result.domain,
      verifiedAt: result.verifiedAt!,
    },
    organizationName: parsed.organizationName,
  });

  // Sign with server's key (vc-jwt pattern from credentials.ts)
  const vcAsRecord = unsignedVc as unknown as Record<string, unknown>;
  const { signingInput } = prepareVcJwtProof(vcAsRecord, signer.algorithm, {
    verificationMethod: signer.id,
  });
  const dataToSign = new TextEncoder().encode(signingInput);
  const signatureBytes = await signer.sign(dataToSign);
  const jwt = completeVcJwtProof(signingInput, signatureBytes);

  const signedCredential = {
    ...unsignedVc,
    proof: { type: "JsonWebSignature2020", jwt },
  };

  // Delete challenge from store (single-use)
  challengeStore.delete(challengeId);

  logger.info(
    { domain: result.domain, issuerDid: parsed.issuerDid, fingerprint: parsed.keyFingerprint },
    "Key attestation credential issued via domain verification",
  );

  return c.json(signedCredential);
});

// ─── POST /attestation/attest-by-vc ──────────────────────────────────

attestation.post("/attestation/attest-by-vc", async (c) => {
  const body = await c.req.json();
  const parsed = attestByVcSchema.parse(body);
  const logger = getLogger();

  // Verify the business VC
  const vcResult = await verifyBusinessVc(parsed.businessVc);

  if (!vcResult.verification.verified) {
    throw new ValidationError(
      "Business VC verification failed: " +
        (vcResult.verification.checks
          .filter((check) => !check.passed)
          .map((check) => check.detail ?? check.name)
          .join("; ") || "unknown error"),
    );
  }

  if (!vcResult.identity) {
    throw new AttestationError(
      "Could not extract identity from business VC",
    );
  }

  const organizationName = vcResult.identity.organizationName ?? "Unknown Organization";

  // Extract domain from identity if available, otherwise use subjectId
  const verifiedDomain = vcResult.identity.additionalClaims["domain"] as string
    ?? vcResult.identity.subjectId
    ?? "unknown";

  // Extract the business VC's ID for sourceCredentialId
  let sourceCredentialId: string | undefined;
  if (typeof parsed.businessVc === "object" && parsed.businessVc !== null) {
    const vcObj = parsed.businessVc as Record<string, unknown>;
    sourceCredentialId = typeof vcObj["id"] === "string" ? vcObj["id"] : undefined;
  }

  // Build unsigned Key Attestation VC
  const signer = requireSigner();
  const unsignedVc = createKeyAttestationVC({
    opencredDid: signer.id,
    issuerDid: parsed.issuerDid,
    issuerKeyJwk: parsed.publicKeyJwk,
    keyFingerprint: parsed.keyFingerprint,
    keyAlgorithm: parsed.keyAlgorithm,
    verificationMethodId: parsed.verificationMethodId,
    identityVerification: {
      method: "business-vc",
      verifiedDomain,
      verifiedAt: new Date().toISOString(),
      sourceCredentialId,
    },
    organizationName,
  });

  // Sign with server's key
  const vcAsRecord = unsignedVc as unknown as Record<string, unknown>;
  const { signingInput } = prepareVcJwtProof(vcAsRecord, signer.algorithm, {
    verificationMethod: signer.id,
  });
  const dataToSign = new TextEncoder().encode(signingInput);
  const signatureBytes = await signer.sign(dataToSign);
  const jwt = completeVcJwtProof(signingInput, signatureBytes);

  const signedCredential = {
    ...unsignedVc,
    proof: { type: "JsonWebSignature2020", jwt },
  };

  logger.info(
    { issuerDid: parsed.issuerDid, fingerprint: parsed.keyFingerprint, organizationName },
    "Key attestation credential issued via business VC",
  );

  return c.json(signedCredential);
});

export { attestation, challengeStore };
