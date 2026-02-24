import { Hono } from "hono";
import { z } from "zod";
import { ValidationError, NotImplementedError } from "@opencred/shared";

// ---------------------------------------------------------------------------
// Certificate Authority Adapter — Type C Extension Point
// ---------------------------------------------------------------------------
//
// The CertificateAuthorityAdapter interface defines the contract that concrete
// CA integrations must satisfy.  OpenCred ships with **no** built-in
// implementation (v1 is an extension-point only).  Implementors can register
// an adapter at startup to enable "Type C" onboarding where DSCs are
// requested on-the-fly from a Certificate Authority.
//
// A concrete adapter might talk to an EJBCA REST API, an AWS Private CA, a
// Sectigo / DigiCert API, or any proprietary government PKI gateway.
//
// Security notes:
//   - The adapter MUST NOT accept or handle raw private key material.
//     DSC requests are CSR-based — the private key stays with the requester.
//   - Adapters SHOULD validate the CSR format before forwarding to the CA.
//   - Adapter errors MUST be wrapped in OpenCredError subclasses so that the
//     error handler never leaks CA-internal details in the HTTP response.
// ---------------------------------------------------------------------------

/**
 * Parameters for requesting a Document Signer Certificate (DSC) from a CA.
 *
 * The `csr` field carries a PEM-encoded PKCS#10 Certificate Signing Request.
 * The private key corresponding to the CSR never leaves the requester — only
 * the public key is embedded in the CSR.
 */
export interface DscRequestParams {
  /** PEM-encoded PKCS#10 Certificate Signing Request */
  csr: string;

  /** Two-letter ISO 3166-1 country code of the requesting authority */
  countryCode: string;

  /** Organisation name for the DSC subject (e.g. "Immigration Department") */
  organisation: string;

  /** Common name for the DSC subject (e.g. "NF Document Signer 2025") */
  commonName: string;

  /**
   * Requested key algorithm for the DSC.
   * Typical values: "EC-P256", "EC-P384", "RSA-2048", "RSA-4096".
   */
  keyAlgorithm?: string;

  /**
   * Requested validity period in days.
   * The CA may override this based on its own policy.
   */
  validityDays?: number;
}

/**
 * Result returned when a DSC request is submitted to the CA.
 */
export interface DscRequestResult {
  /** Unique identifier for the DSC request assigned by the CA (or adapter) */
  requestId: string;

  /** Current status of the request immediately after submission */
  status: DscRequestStatusCode;

  /**
   * Estimated time until the DSC is issued (ISO 8601 duration or date-time).
   * May be undefined if the CA does not provide an estimate.
   */
  estimatedCompletion?: string;
}

/**
 * Status codes for a DSC request lifecycle.
 */
export type DscRequestStatusCode = "pending" | "approved" | "rejected" | "issued";

/**
 * Full status of a pending DSC request, returned by `checkStatus`.
 */
export interface DscRequestStatus {
  /** The request identifier originally returned by `requestDSC` */
  requestId: string;

  /** Current status of the DSC request */
  status: DscRequestStatusCode;

  /**
   * PEM-encoded DSC certificate chain (leaf first).
   * Present only when `status` is "issued".
   */
  certificateChain?: string[];

  /** Human-readable reason if the request was rejected */
  rejectionReason?: string;

  /** Timestamp when the status was last updated (ISO 8601) */
  updatedAt?: string;
}

/**
 * Extension-point interface for Certificate Authority integrations.
 *
 * Concrete implementations connect OpenCred to a specific CA backend
 * (e.g. EJBCA, AWS Private CA, government PKI gateway).
 *
 * This interface is intentionally minimal — adapters handle the mapping
 * between OpenCred's domain model and the CA's proprietary API.
 *
 * @example
 * ```typescript
 * class EjbcaAdapter implements CertificateAuthorityAdapter {
 *   async requestDSC(params: DscRequestParams): Promise<DscRequestResult> {
 *     // Forward CSR to EJBCA REST API ...
 *   }
 *   async checkStatus(requestId: string): Promise<DscRequestStatus> {
 *     // Poll EJBCA for certificate issuance status ...
 *   }
 * }
 * ```
 */
export interface CertificateAuthorityAdapter {
  /** Submit a DSC (Document Signer Certificate) request to the CA. */
  requestDSC(params: DscRequestParams): Promise<DscRequestResult>;

  /** Check the status of a previously submitted DSC request. */
  checkStatus(requestId: string): Promise<DscRequestStatus>;
}

// ---------------------------------------------------------------------------
// Zod schemas for request validation
// ---------------------------------------------------------------------------

const caRequestSchema = z.object({
  csr: z.string().min(1, "csr must be a non-empty PEM string"),
  countryCode: z
    .string()
    .length(2, "countryCode must be a 2-letter ISO 3166-1 code")
    .regex(/^[A-Z]{2}$/, "countryCode must be uppercase letters"),
  organisation: z.string().min(1, "organisation must not be empty"),
  commonName: z.string().min(1, "commonName must not be empty"),
  keyAlgorithm: z.string().optional(),
  validityDays: z.number().int().positive().optional(),
});

const caStatusSchema = z.object({
  requestId: z.string().min(1, "requestId must not be empty"),
});

// ---------------------------------------------------------------------------
// Route dependencies
// ---------------------------------------------------------------------------

export interface CaRequestRoutesDeps {
  /**
   * The registered CA adapter, or `undefined` when no CA integration is
   * configured.  When undefined the endpoint returns 501 Not Implemented.
   */
  caAdapter?: CertificateAuthorityAdapter;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create Hono routes for the Type C CA-request onboarding flow.
 *
 * - `POST /ca-request` — submit a new DSC request via the configured CA adapter
 * - `POST /ca-request/status` — check the status of an existing DSC request
 *
 * When no `caAdapter` is provided in deps, both endpoints return
 * 501 Not Implemented with a clear error message.
 */
export function createCaRequestRoutes(deps: CaRequestRoutesDeps) {
  const { caAdapter } = deps;
  const caRequest = new Hono();

  // POST /ca-request — submit a DSC request
  caRequest.post("/ca-request", async (c) => {
    if (!caAdapter) {
      throw new NotImplementedError(
        "Certificate Authority adapter is not configured. " +
          "Type C onboarding requires a CA adapter to be registered at startup.",
      );
    }

    const rawBody = await c.req.json();
    const parsed = caRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const result = await caAdapter.requestDSC(parsed.data);

    return c.json(
      {
        requestId: result.requestId,
        status: result.status,
        ...(result.estimatedCompletion && { estimatedCompletion: result.estimatedCompletion }),
      },
      202,
    );
  });

  // POST /ca-request/status — check status of a DSC request
  caRequest.post("/ca-request/status", async (c) => {
    if (!caAdapter) {
      throw new NotImplementedError(
        "Certificate Authority adapter is not configured. " +
          "Type C onboarding requires a CA adapter to be registered at startup.",
      );
    }

    const rawBody = await c.req.json();
    const parsed = caStatusSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const status = await caAdapter.checkStatus(parsed.data.requestId);

    return c.json({
      requestId: status.requestId,
      status: status.status,
      ...(status.certificateChain && { certificateChain: status.certificateChain }),
      ...(status.rejectionReason && { rejectionReason: status.rejectionReason }),
      ...(status.updatedAt && { updatedAt: status.updatedAt }),
    });
  });

  return caRequest;
}
