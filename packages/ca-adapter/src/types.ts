/**
 * CA Adapter types for OpenCred Phase 3.
 *
 * These types define the extension point for Certificate Authority integration.
 * User Type 2 (Issuer Seeking DSC) uses these to request a DSC through a CA
 * facilitated by OpenCred. Once issued, the DSC is imported and the issuer
 * becomes User Type 1 (Issuer with DSC).
 *
 * Security invariant: the CA adapter receives CSRs or public keys, NEVER
 * private keys. All key generation and CSR creation happen locally on the
 * issuer's machine.
 */

/** Supported key algorithms for DSC requests. */
export type KeyAlgorithm = "ES256" | "ES384" | "ES512" | "RS256" | "EdDSA";

/**
 * Subject information for a DSC request.
 * Contains the organizational details needed by the CA.
 */
export interface DscSubjectInfo {
  /** Organization name (e.g., "Ministry of Foreign Affairs") */
  organizationName: string;
  /** ISO 3166-1 alpha-2 country code (e.g., "NL", "US") */
  country: string;
  /** Domain name for domain-validated certificates */
  domain?: string;
  /** Organization unit (optional) */
  organizationalUnit?: string;
  /** Common name (optional, defaults to organizationName) */
  commonName?: string;
}

/**
 * A request for a DSC from a Certificate Authority.
 *
 * Security invariant: contains a CSR or public key — NEVER a private key.
 * The private key stays on the issuer's machine at all times.
 */
export interface DscRequest {
  /** Subject information for the certificate */
  subject: DscSubjectInfo;
  /**
   * PEM-encoded Certificate Signing Request.
   * The CSR is generated locally by the issuer — the private key never
   * leaves their machine.
   */
  csr: string;
  /** Preferred key algorithm (informational; the CSR already encodes the key) */
  keyAlgorithm?: KeyAlgorithm;
  /** Optional metadata for the CA (e.g., justification, reference number) */
  metadata?: Record<string, string>;
}

/** Status values for a DSC request. */
export type DscRequestStatusCode = "pending" | "approved" | "rejected" | "issued";

/**
 * Result returned when a DSC request is initially submitted.
 */
export interface DscRequestResult {
  /** Unique identifier for tracking this request */
  requestId: string;
  /** Current status of the request */
  status: DscRequestStatusCode;
  /** Estimated time until the request is processed (ISO 8601 duration or date) */
  estimatedCompletion?: string;
  /** Human-readable message from the CA */
  message?: string;
}

/**
 * Status of a previously submitted DSC request.
 */
export interface DscRequestStatus {
  /** Unique identifier for this request */
  requestId: string;
  /** Current status */
  status: DscRequestStatusCode;
  /**
   * PEM-encoded DSC certificate, present only when status is "issued".
   * Once received, the issuer imports this to become User Type 1.
   */
  certificate?: string;
  /**
   * PEM-encoded certificate chain (intermediate CAs), present only when
   * status is "issued". Order: issuer cert first, root last.
   */
  certificateChain?: string[];
  /** Reason for rejection, present only when status is "rejected" */
  rejectionReason?: string;
  /** Human-readable message from the CA */
  message?: string;
  /** When the status was last updated (ISO 8601) */
  updatedAt?: string;
}

/**
 * Configuration for creating a CA adapter instance.
 */
export interface CaAdapterConfig {
  /** Identifier for the adapter type (e.g., "noop", "acme", "custom") */
  type: string;
  /** Adapter-specific configuration options */
  options?: Record<string, unknown>;
}

/**
 * The CertificateAuthorityAdapter interface.
 *
 * This is an extension point — no real CA implementations ship in v2.
 * Implementors connect to their CA's API and translate between OpenCred's
 * types and the CA's wire format.
 *
 * Flow:
 * 1. Issuer generates a key pair locally
 * 2. Issuer creates a CSR locally (private key never leaves their machine)
 * 3. `requestDSC(request)` submits the CSR to the CA
 * 4. `checkStatus(requestId)` polls until the DSC is issued
 * 5. Issuer imports the issued DSC and becomes User Type 1
 */
export interface CertificateAuthorityAdapter {
  /** Human-readable name of this adapter (e.g., "ACME CA", "No-Op") */
  readonly name: string;

  /**
   * Submit a DSC request to the Certificate Authority.
   *
   * @param request - The DSC request containing subject info and CSR
   * @returns The result including a request ID for status tracking
   * @throws CaAdapterError if the request cannot be submitted
   */
  requestDSC(request: DscRequest): Promise<DscRequestResult>;

  /**
   * Check the status of a previously submitted DSC request.
   *
   * @param requestId - The request ID returned by requestDSC()
   * @returns The current status, including the certificate when issued
   * @throws CaAdapterError if the status cannot be retrieved
   */
  checkStatus(requestId: string): Promise<DscRequestStatus>;
}
