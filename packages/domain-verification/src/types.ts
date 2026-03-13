/**
 * Domain Verification types.
 *
 * Defines challenge methods, statuses, and data structures used for
 * verifying domain ownership in the OpenCred-Attested flow.
 */

/** Supported domain verification challenge methods. */
export type ChallengeMethod = "dns-txt" | "http";

/** Status of a domain verification challenge. */
export type ChallengeStatus = "pending" | "verified" | "expired" | "failed";

/** A domain ownership challenge awaiting verification. */
export interface DomainChallenge {
  /** Unique challenge identifier. */
  id: string;
  /** The domain being verified. */
  domain: string;
  /** Verification method (dns-txt or http). */
  method: ChallengeMethod;
  /** The secret token the domain owner must publish. */
  token: string;
  /** Current status of the challenge. */
  status: ChallengeStatus;
  /** When this challenge was created. */
  createdAt: Date;
  /** When this challenge expires. */
  expiresAt: Date;
  /** When the challenge was verified (only set if status is 'verified'). */
  verifiedAt?: Date;
}

/** Details returned to the caller after challenge generation. */
export interface ChallengeDetails {
  /** Unique challenge identifier. */
  challengeId: string;
  /** The domain being verified. */
  domain: string;
  /** Verification method. */
  method: ChallengeMethod;
  /** The secret token to publish. */
  token: string;
  /** When this challenge expires. */
  expiresAt: Date;
  /** Human-readable instructions for completing the challenge. */
  instructions: string;
}

/** Result of a domain verification attempt. */
export interface DomainVerificationResult {
  /** Whether the domain ownership was verified. */
  verified: boolean;
  /** The domain that was being verified. */
  domain: string;
  /** The verification method used. */
  method: ChallengeMethod;
  /** ISO timestamp of verification (only present if verified). */
  verifiedAt?: string;
  /** Error message (only present if verification failed). */
  error?: string;
}
