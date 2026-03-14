/**
 * Certificate Authority Adapter — extension point interface.
 *
 * Defines the contract for integrating with external Certificate Authorities
 * to request DSCs (Document Signer Certificates) on behalf of issuers.
 *
 * This is used for User Type 2 (Issuer Seeking DSC): after OpenCred verifies
 * the issuer's identity (via domain ownership or business VC), it can submit
 * a DSC request to a CA through an adapter implementing this interface.
 *
 * No implementations are provided in this package — concrete adapters for
 * specific CAs (e.g., government PKI, commercial CAs) will be added as
 * separate packages or plugins.
 */

import type { PublicKeyJwk, IdentityVerification } from "./types.js";
import type { BusinessIdentity } from "./business-vc-types.js";

/** A request for a Document Signer Certificate from a CA. */
export interface DSCRequest {
  /** The DID of the subject (issuer) requesting the DSC. */
  subjectDid: string;
  /** The organization name for the certificate subject. */
  organizationName: string;
  /** The issuer's public key in JWK format. */
  publicKeyJwk: PublicKeyJwk;
  /** The key algorithm identifier (e.g., "P-256", "Ed25519"). */
  keyAlgorithm: string;
  /** Identity evidence — either domain verification or business VC identity. */
  identityEvidence: IdentityVerification | BusinessIdentity;
}

/** Status of a DSC request submitted to a CA. */
export interface DSCRequestStatus {
  /** Unique identifier assigned by the CA for tracking. */
  requestId: string;
  /** Current status of the request. */
  status: "pending" | "approved" | "rejected" | "issued";
  /** PEM-encoded DSC, present only when status is "issued". */
  dscPem?: string;
  /** Reason for rejection, present only when status is "rejected". */
  rejectionReason?: string;
  /** ISO 8601 timestamp of the last status update. */
  updatedAt: string;
}

/**
 * Adapter interface for integrating with a Certificate Authority.
 *
 * Implementations must handle the specifics of a particular CA's API,
 * authentication, and certificate lifecycle.
 */
export interface CertificateAuthorityAdapter {
  /** Human-readable name of the CA this adapter connects to. */
  readonly name: string;

  /**
   * Submit a DSC request to the CA.
   *
   * @param request - The DSC request details.
   * @returns A promise resolving to the CA-assigned request ID.
   */
  requestDSC(request: DSCRequest): Promise<{ requestId: string }>;

  /**
   * Check the status of a previously submitted DSC request.
   *
   * @param requestId - The CA-assigned request ID from requestDSC.
   * @returns A promise resolving to the current status.
   */
  checkStatus(requestId: string): Promise<DSCRequestStatus>;
}
