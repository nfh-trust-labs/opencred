import type { DeDiClient } from "@opencred/dedi-client";
import type { DIDResolver } from "@opencred/did";
import type { SdJwtVcVerifyOptions } from "./sd-jwt-vc.js";

/**
 * Result codes for credential verification.
 */
export type VerificationResultCode =
  | "VALID"
  | "REVOKED"
  | "EXPIRED"
  | "INVALID"
  | "UNRESOLVABLE"
  | "CONTEXT_MISSING";

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
export type CredentialFormat = "data-integrity" | "jws-2020" | "vc-jwt" | "sd-jwt-vc" | "jws";

/**
 * Configuration for the verification engine.
 */
export interface VerifierConfig {
  didResolver?: DIDResolver;
  dediClient?: DeDiClient;
  /**
   * PEM-encoded trust anchor certificates (e.g. CSCA roots) used by the X.509
   * chain check. Each entry must be a complete PEM block beginning with
   * `-----BEGIN CERTIFICATE-----`. When a credential carries an `x5c` chain,
   * the chain MUST terminate in one of these anchors for the chain check to
   * pass; otherwise the chain check fails closed with a configuration error.
   *
   * For credentials that do not include an `x5c` chain (e.g. self-published
   * keys via did:web), trust anchors are not required.
   */
  trustAnchors?: string[];
  /**
   * SD-JWT VC verification options forwarded to `verifySdJwtVc`.
   *
   * Callers handling a presented (as opposed to issued) SD-JWT VC MUST
   * supply `expectedAudience` and `expectedNonce` here — per SD-JWT VC
   * §4.3.1, the KB-JWT's `aud` and `nonce` MUST be validated against
   * the expected values to prevent replay and presentation misuse.
   * `expectedVct` pins the credential type.
   */
  sdJwtVc?: SdJwtVcVerifyOptions;
}

/**
 * Input to the verification engine — either a VerifiableCredential object
 * (Data Integrity) or a compact string (VC-JWT / SD-JWT VC).
 */
export type VerificationInput = Record<string, unknown> | string;
