import type { KeyObject } from "node:crypto";
import type { DeDiClient } from "@opencred/dedi-client";
import type { DIDResolver } from "@opencred/did";

/**
 * Result codes for credential verification.
 */
export type VerificationResultCode =
  | "VALID"
  | "REVOKED"
  | "EXPIRED"
  | "INVALID"
  | "UNRESOLVABLE"
  | "ATTESTATION_INVALID";

/**
 * A single check performed during verification.
 */
export interface VerificationCheck {
  name: string;
  passed: boolean;
  detail?: string;
}

/**
 * The result of a credential verification operation.
 */
export interface CredentialVerificationResult {
  code: VerificationResultCode;
  verified: boolean;
  checks: VerificationCheck[];
}

/**
 * Supported credential formats for verification.
 */
export type CredentialFormat = "data-integrity" | "vc-jwt" | "sd-jwt-vc" | "jws";

/**
 * Configuration for the verification engine.
 */
export interface VerifierConfig {
  didResolver?: DIDResolver;
  dediClient?: DeDiClient;
  /** Public key (not private) of OpenCred for attestation VC signature verification. */
  opencredPublicKey?: KeyObject;
  /** Public DSC certificate (PEM) for attestation chain validation (not a secret). */
  opencredDscCertificate?: string;
}

/**
 * Input to the verification engine — either a VerifiableCredential object
 * (Data Integrity) or a compact string (VC-JWT / SD-JWT VC).
 */
export type VerificationInput = Record<string, unknown> | string;
