/**
 * Business VC identity verification.
 *
 * Verifies a W3C Verifiable Credential presented as identity proof
 * by an OpenCred-Attested issuer (User Type 3). Delegates cryptographic
 * verification to the existing verification engine and then extracts
 * a normalized BusinessIdentity from the credential's subject.
 */

import { AttestationError } from "@opencred/shared";
import type {
  CredentialVerificationResult,
  VerificationInput,
  VerifierConfig,
} from "@opencred/verification";
import { verifyCredential } from "@opencred/verification";
import type { BusinessIdentity, BusinessVcVerificationResult } from "./business-vc-types.js";

/**
 * Verifies business VCs presented as identity proof and extracts
 * issuer identity information from them.
 */
export class BusinessVcVerifier {
  private readonly verifierConfig: VerifierConfig;

  /**
   * @param verifierConfig - Configuration for the underlying credential verifier.
   */
  constructor(verifierConfig: VerifierConfig = {}) {
    this.verifierConfig = verifierConfig;
  }

  /**
   * Verify a business VC and extract identity information.
   *
   * 1. Verifies the credential using the verification engine (signature, dates, revocation).
   * 2. If valid, extracts a normalized BusinessIdentity from the credentialSubject.
   *
   * @param credential - A VerificationInput (object or JWT string).
   * @returns Verification result with extracted identity on success.
   */
  async verifyBusinessVc(
    credential: VerificationInput,
  ): Promise<BusinessVcVerificationResult> {
    // Step 1: Verify the credential cryptographically
    let verificationResult: CredentialVerificationResult;
    try {
      verificationResult = await verifyCredential(credential, this.verifierConfig);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown verification error";
      return {
        verified: false,
        error: `Credential verification failed: ${message}`,
      };
    }

    if (!verificationResult.verified) {
      return {
        verified: false,
        verificationResult,
        error: `Credential is not valid: ${verificationResult.code}`,
      };
    }

    // Step 2: Extract identity from the credential
    // For object credentials, extract directly. For JWT strings, decode first.
    let credentialObject: Record<string, unknown>;
    if (typeof credential === "object" && credential !== null) {
      credentialObject = credential;
    } else if (typeof credential === "string") {
      credentialObject = decodeCredentialFromString(credential);
    } else {
      return {
        verified: false,
        verificationResult,
        error: "Unable to extract identity: unsupported credential format",
      };
    }

    try {
      const identity = extractIssuerIdentity(credentialObject);
      return {
        verified: true,
        identity,
        verificationResult,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown extraction error";
      return {
        verified: false,
        verificationResult,
        error: `Identity extraction failed: ${message}`,
      };
    }
  }
}

/**
 * Extract a normalized BusinessIdentity from a credential object.
 *
 * Handles multiple credential schemas by looking for common fields
 * across business registration, LEI, and commercial register credentials.
 *
 * @param credential - A credential object with a credentialSubject.
 * @returns Normalized BusinessIdentity.
 * @throws AttestationError if the credential lacks a usable subject or organization name.
 */
export function extractIssuerIdentity(
  credential: Record<string, unknown>,
): BusinessIdentity {
  const subject = extractSubject(credential);

  if (!subject || typeof subject !== "object") {
    throw new AttestationError(
      "Credential does not contain a valid credentialSubject",
    );
  }

  const organizationName = extractOrganizationName(subject);
  if (!organizationName) {
    throw new AttestationError(
      "credentialSubject does not contain an organization name",
    );
  }

  return {
    organizationName,
    legalName: extractStringField(subject, [
      "legalName",
      "officialName",
      "registeredName",
    ]),
    registrationNumber: extractStringField(subject, [
      "registrationNumber",
      "leiCode",
      "lei",
      "companyNumber",
      "businessRegistrationNumber",
      "taxId",
    ]),
    country: extractStringField(subject, [
      "country",
      "countryCode",
      "jurisdiction",
      "addressCountry",
    ]),
    domain: extractStringField(subject, [
      "domain",
      "website",
      "url",
    ]),
    sourceCredentialId: typeof credential["id"] === "string"
      ? credential["id"]
      : undefined,
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * Extract the credentialSubject from a credential, handling both
 * single-subject and array-subject formats.
 */
function extractSubject(
  credential: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const raw = credential["credentialSubject"];

  if (Array.isArray(raw)) {
    // Use the first subject if array
    const first = raw[0];
    if (first && typeof first === "object") {
      return first as Record<string, unknown>;
    }
    return undefined;
  }

  if (raw && typeof raw === "object") {
    return raw as Record<string, unknown>;
  }

  // For VC-JWT: check if there's a nested "vc" claim
  const vc = credential["vc"];
  if (vc && typeof vc === "object") {
    const vcObj = vc as Record<string, unknown>;
    return extractSubject(vcObj);
  }

  return undefined;
}

/**
 * Extract an organization name from a credential subject, trying
 * multiple common field names across credential schemas.
 */
function extractOrganizationName(
  subject: Record<string, unknown>,
): string | undefined {
  const candidates = [
    "organizationName",
    "name",
    "legalName",
    "officialName",
    "registeredName",
    "companyName",
    "entityName",
    "businessName",
  ];

  for (const field of candidates) {
    const value = subject[field];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }

  // Handle nested organization objects (e.g., Schema.org style)
  const org = subject["organization"];
  if (org && typeof org === "object") {
    const orgObj = org as Record<string, unknown>;
    const orgName = orgObj["name"];
    if (typeof orgName === "string" && orgName.trim().length > 0) {
      return orgName.trim();
    }
  }

  return undefined;
}

/**
 * Try to extract a string value from a subject by checking
 * multiple candidate field names.
 */
function extractStringField(
  subject: Record<string, unknown>,
  candidates: string[],
): string | undefined {
  for (const field of candidates) {
    const value = subject[field];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

/**
 * Decode a credential from a JWT or SD-JWT string to extract the payload.
 * Used to access credentialSubject for identity extraction.
 */
function decodeCredentialFromString(input: string): Record<string, unknown> {
  // SD-JWT: take the part before the first ~
  const jwtPart = input.includes("~") ? input.split("~")[0] : input;

  const parts = jwtPart.split(".");
  if (parts.length !== 3) {
    throw new AttestationError("Unable to decode credential string: not a valid JWT");
  }

  try {
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString(),
    ) as Record<string, unknown>;

    // VC-JWT wraps the credential in a "vc" claim
    if (payload["vc"] && typeof payload["vc"] === "object") {
      return payload["vc"] as Record<string, unknown>;
    }

    // JWS or other formats may have the credential directly in the payload
    return payload;
  } catch {
    throw new AttestationError("Unable to decode credential string: invalid JWT payload");
  }
}
