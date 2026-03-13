/**
 * Domain verification challenge manager.
 *
 * Creates, tracks, verifies, and expires domain ownership challenges.
 * Supports both DNS TXT and HTTP challenge methods.
 *
 * Security considerations:
 * - All tokens generated with CSPRNG (crypto.randomBytes)
 * - Challenge tokens and secrets are never logged
 * - Expired challenges are automatically cleaned up
 */

import { randomBytes, randomUUID } from "node:crypto";
import { AttestationError } from "@opencred/shared";
import type {
  ChallengeDetails,
  ChallengeMethod,
  DomainChallenge,
  DomainVerificationResult,
} from "./types.js";
import { DNS_TXT_PREFIX } from "./dns-verifier.js";
import { verifyDnsTxtChallenge } from "./dns-verifier.js";
import { verifyHttpChallenge, WELL_KNOWN_PATH } from "./http-verifier.js";

/** Default challenge TTL: 24 hours. */
const CHALLENGE_TTL_MS = 24 * 60 * 60 * 1000;

/** Number of bytes for the challenge token (256-bit entropy). */
const TOKEN_BYTES = 32;

// ─── Challenge Store ──────────────────────────────────────────────────

/**
 * In-memory challenge store with TTL-based expiry.
 *
 * Stores pending domain verification challenges and automatically
 * cleans up expired entries on access.
 */
export class ChallengeStore {
  private readonly challenges = new Map<string, DomainChallenge>();

  /** Create and store a new challenge. */
  create(
    domain: string,
    method: ChallengeMethod,
    token: string,
  ): DomainChallenge {
    const now = new Date();
    const challenge: DomainChallenge = {
      id: randomUUID(),
      domain,
      method,
      token,
      status: "pending",
      createdAt: now,
      expiresAt: new Date(now.getTime() + CHALLENGE_TTL_MS),
    };
    this.challenges.set(challenge.id, challenge);
    return challenge;
  }

  /** Retrieve a challenge by ID. Returns undefined if not found or expired. */
  get(id: string): DomainChallenge | undefined {
    const challenge = this.challenges.get(id);
    if (!challenge) return undefined;
    if (challenge.expiresAt <= new Date()) {
      challenge.status = "expired";
      this.challenges.delete(id);
      return undefined;
    }
    return challenge;
  }

  /** Delete a challenge by ID. */
  delete(id: string): boolean {
    return this.challenges.delete(id);
  }

  /** Remove all expired challenges. Returns the count of removed entries. */
  cleanup(): number {
    const now = new Date();
    let removed = 0;
    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt <= now) {
        this.challenges.delete(id);
        removed++;
      }
    }
    return removed;
  }

  /** Return the number of active (non-expired) challenges. */
  get size(): number {
    return this.challenges.size;
  }
}

// ─── Challenge Generator ──────────────────────────────────────────────

/**
 * Generate a domain ownership challenge.
 *
 * Creates a cryptographically random token (256-bit entropy via CSPRNG)
 * that the domain owner must publish at the appropriate location:
 * - DNS TXT: Add a TXT record with value `opencred-verify=<token>`
 * - HTTP: Place the token at `https://<domain>/.well-known/opencred-challenge/<challengeId>`
 *
 * @param domain - The domain to verify ownership of
 * @param method - The challenge method ('dns-txt' or 'http')
 * @returns Challenge details including token and instructions
 */
export function generateChallenge(
  domain: string,
  method: ChallengeMethod,
): ChallengeDetails {
  validateDomain(domain);
  validateMethod(method);

  const token = randomBytes(TOKEN_BYTES).toString("hex");
  const challengeId = randomUUID();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);

  let instructions: string;
  if (method === "dns-txt") {
    instructions = `Add a DNS TXT record to ${domain} with value: ${DNS_TXT_PREFIX}${token}`;
  } else {
    instructions = `Place the token at https://${domain}/${WELL_KNOWN_PATH}/${challengeId}`;
  }

  return {
    challengeId,
    domain,
    method,
    token,
    expiresAt,
    instructions,
  };
}

// ─── Challenge Manager ────────────────────────────────────────────────

/**
 * Verify domain ownership using a previously stored challenge.
 *
 * Retrieves the challenge from the store, dispatches to the appropriate
 * verifier (DNS TXT or HTTP), and updates the challenge status.
 *
 * @param challengeId - The ID of the stored challenge
 * @param store - The challenge store containing the challenge
 * @returns Verification result with domain, method, and status
 */
export async function verifyDomainOwnership(
  challengeId: string,
  store: ChallengeStore,
): Promise<DomainVerificationResult> {
  if (!challengeId) {
    return {
      verified: false,
      domain: "",
      method: "dns-txt",
      error: "Challenge ID is required",
    };
  }

  const challenge = store.get(challengeId);
  if (!challenge) {
    return {
      verified: false,
      domain: "",
      method: "dns-txt",
      error: "Challenge not found or expired",
    };
  }

  if (challenge.status === "verified") {
    return {
      verified: false,
      domain: challenge.domain,
      method: challenge.method,
      error: "Challenge has already been verified",
    };
  }

  let verified: boolean;
  try {
    if (challenge.method === "dns-txt") {
      verified = await verifyDnsTxtChallenge(challenge.domain, challenge.token);
    } else {
      verified = await verifyHttpChallenge(
        challenge.domain,
        challenge.id,
        challenge.token,
      );
    }
  } catch (err) {
    challenge.status = "failed";
    const message =
      err instanceof Error ? err.message : "Verification failed";
    return {
      verified: false,
      domain: challenge.domain,
      method: challenge.method,
      error: message,
    };
  }

  if (verified) {
    challenge.status = "verified";
    challenge.verifiedAt = new Date();
    return {
      verified: true,
      domain: challenge.domain,
      method: challenge.method,
      verifiedAt: challenge.verifiedAt.toISOString(),
    };
  }

  challenge.status = "failed";
  return {
    verified: false,
    domain: challenge.domain,
    method: challenge.method,
    error: "Domain verification failed: expected record or response not found",
  };
}

// ─── Validation Helpers ───────────────────────────────────────────────

/**
 * Validate a domain name.
 * Rejects empty strings, domains with protocols, paths, and overly long names.
 */
function validateDomain(domain: string): void {
  if (!domain) {
    throw new AttestationError("Domain is required");
  }
  if (domain.includes("://")) {
    throw new AttestationError("Domain must not include a protocol (e.g., https://)");
  }
  if (domain.includes("/")) {
    throw new AttestationError("Domain must not include a path");
  }
  if (domain.length > 253) {
    throw new AttestationError("Domain name exceeds maximum length (253 characters)");
  }
}

/**
 * Validate the challenge method.
 */
function validateMethod(method: ChallengeMethod): void {
  if (method !== "dns-txt" && method !== "http") {
    throw new AttestationError(
      `Invalid verification method: ${method}. Must be 'dns-txt' or 'http'`,
    );
  }
}
