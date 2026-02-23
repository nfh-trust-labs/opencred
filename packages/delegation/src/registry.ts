import { DelegationError } from "@opencred/shared";
import type { DeDiClient, DelegationRecord } from "@opencred/dedi-client";
import type {
  DelegationCertificate,
  RegisterDelegationParams,
  ResolveDelegationParams,
} from "./types.js";

/**
 * Register a signed delegation certificate in DeDi.
 *
 * The delegation authority and OpenCred's signing key are recorded in DeDi
 * so that verifiers can resolve the delegation chain during credential
 * verification (PRD Section 8.4).
 *
 * @param client - The DeDi client instance.
 * @param params - Registration parameters including the signed certificate.
 * @returns The DeDi delegation record.
 * @throws {DelegationError} if the certificate is unsigned or registration fails.
 */
export async function registerDelegation(
  client: DeDiClient,
  params: RegisterDelegationParams,
): Promise<DelegationRecord> {
  const { certificate } = params;

  if (!certificate.proof) {
    throw new DelegationError(
      "Cannot register an unsigned delegation certificate in DeDi",
    );
  }

  validateCertificateForRegistration(certificate);

  try {
    return await client.registerDelegation({
      id: certificate.id,
      issuerDid: certificate.delegator.id,
      delegateDid: certificate.delegatee.id,
      scope: [
        ...certificate.scope.credentialTypes,
        ...certificate.scope.namespaces,
      ],
      validFrom: certificate.validFrom,
      validUntil: certificate.validUntil,
      certificate,
    });
  } catch (error) {
    if (error instanceof DelegationError) throw error;
    throw new DelegationError(
      `Failed to register delegation in DeDi: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

/**
 * Resolve a delegation certificate from DeDi by its ID.
 *
 * Used during verification to retrieve the delegation certificate when
 * the credential references it by URL rather than embedding it inline.
 *
 * @param client - The DeDi client instance.
 * @param params - Resolution parameters including the delegation ID.
 * @returns The delegation certificate from the DeDi record.
 * @throws {DelegationError} if resolution fails or the record is invalid.
 */
export async function resolveDelegation(
  client: DeDiClient,
  params: ResolveDelegationParams,
): Promise<DelegationCertificate> {
  if (!params.delegationId?.trim()) {
    throw new DelegationError("delegationId is required");
  }

  try {
    const record = await client.resolveDelegation(params.delegationId);

    if (!record.certificate) {
      throw new DelegationError(
        `DeDi record ${params.delegationId} has no certificate`,
      );
    }

    return record.certificate as DelegationCertificate;
  } catch (error) {
    if (error instanceof DelegationError) throw error;
    throw new DelegationError(
      `Failed to resolve delegation from DeDi: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
}

function validateCertificateForRegistration(
  certificate: DelegationCertificate,
): void {
  if (!certificate.id) {
    throw new DelegationError("Certificate id is required for registration");
  }
  if (!certificate.delegator?.id) {
    throw new DelegationError("Certificate delegator.id is required for registration");
  }
  if (!certificate.delegatee?.id) {
    throw new DelegationError("Certificate delegatee.id is required for registration");
  }
  if (!certificate.validFrom || !certificate.validUntil) {
    throw new DelegationError(
      "Certificate validFrom and validUntil are required for registration",
    );
  }
}
