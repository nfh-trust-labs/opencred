/**
 * Business VC Verification module.
 *
 * Accepts existing verifiable credentials (business VCs) as identity proof
 * for issuers in the OpenCred-Attested authentication flow. When an issuer
 * doesn't have a DSC, they can prove their identity by presenting a verified
 * business credential.
 *
 * Supports all verification formats: Data Integrity, VC-JWT, SD-JWT VC.
 */

import { VerificationError } from "@opencred/shared";
import { verifyCredential, detectFormat } from "./verifier.js";
import type {
  CredentialVerificationResult,
  VerificationInput,
  VerifierConfig,
} from "./types.js";

// ── Types ────────────────────────────────────────────────────────────

/**
 * Structured identity extracted from a verified business VC's credentialSubject.
 */
export interface ExtractedIdentity {
  /** Organization / legal entity name. */
  organizationName?: string;
  /** Legal Entity Identifier (LEI, DUNS, etc.). */
  organizationIdentifier?: string;
  /** Type of the identifier (e.g., "LEI", "DUNS", "CRN"). */
  identifierType?: string;
  /** Jurisdiction / country of registration. */
  jurisdiction?: string;
  /** The DID or URI of the credential subject. */
  subjectId?: string;
  /** Additional identity claims extracted from the credential subject. */
  additionalClaims: Record<string, unknown>;
}

/**
 * Result of verifying a business VC and extracting identity.
 */
export interface BusinessVcVerificationResult {
  /** The underlying credential verification result. */
  verification: CredentialVerificationResult;
  /** The detected credential format. */
  format: string;
  /** Extracted identity (only populated when verification succeeds). */
  identity: ExtractedIdentity | null;
}

// ── Well-known field mappings ────────────────────────────────────────

/**
 * Maps from well-known credential subject field names to ExtractedIdentity
 * fields. Supports common business VC schemas (LEI, business registration,
 * W3C Traceability, etc.).
 */
const ORG_NAME_FIELDS = [
  "organizationName",
  "legalName",
  "name",
  "companyName",
  "entityName",
  "registeredName",
  "tradeName",
] as const;

const ORG_IDENTIFIER_FIELDS = [
  "organizationIdentifier",
  "leiCode",
  "lei",
  "dunsNumber",
  "registrationNumber",
  "companyNumber",
  "taxId",
  "vatNumber",
  "identifier",
  "globalLocationNumber",
] as const;

const IDENTIFIER_TYPE_FIELDS = [
  "identifierType",
  "identifierScheme",
  "registrationType",
] as const;

const JURISDICTION_FIELDS = [
  "jurisdiction",
  "country",
  "countryOfRegistration",
  "registrationCountry",
  "addressCountry",
  "headquartersAddress",
] as const;

// Fields that are extracted into named properties and should not
// appear a second time in additionalClaims.
const EXTRACTED_FIELD_NAMES = new Set<string>([
  "id",
  ...ORG_NAME_FIELDS,
  ...ORG_IDENTIFIER_FIELDS,
  ...IDENTIFIER_TYPE_FIELDS,
  ...JURISDICTION_FIELDS,
]);

// ── Core API ─────────────────────────────────────────────────────────

/**
 * Verify a business VC and extract the issuer's identity.
 *
 * 1. Detects the credential format (Data Integrity, VC-JWT, SD-JWT VC).
 * 2. Runs the full verification pipeline (signature, dates, revocation).
 * 3. On success, extracts structured identity claims from credentialSubject.
 *
 * @param input  The credential — an object (Data Integrity) or compact string
 *               (VC-JWT / SD-JWT VC).
 * @param config Optional verifier configuration (DID resolver, DeDi client).
 * @returns Verification result together with extracted identity.
 *
 * @throws {VerificationError} If the input is structurally invalid and
 *         cannot even be dispatched to a format-specific verifier.
 */
export async function verifyBusinessVc(
  input: VerificationInput,
  config: VerifierConfig = {},
): Promise<BusinessVcVerificationResult> {
  // Detect format first so we can report it even on failure.
  let format: string;
  try {
    format = detectFormat(input);
  } catch (err) {
    throw new VerificationError(
      err instanceof Error ? err.message : "Unable to detect credential format",
    );
  }

  // Run the full verification pipeline.
  const verification = await verifyCredential(input, config);

  if (!verification.verified) {
    return { verification, format, identity: null };
  }

  // Extract identity from the verified credential.
  const subject = extractSubject(input, format);
  const identity = extractIdentity(subject);

  return { verification, format, identity };
}

// ── Internal helpers ─────────────────────────────────────────────────

/**
 * Pull the credentialSubject out of the raw input based on format.
 */
function extractSubject(
  input: VerificationInput,
  format: string,
): Record<string, unknown> {
  if (format === "data-integrity" || format === "jws") {
    const obj = (typeof input === "object" ? input : {}) as Record<string, unknown>;

    // For JWS format, subject might be in the decoded payload
    if (format === "jws" && typeof input === "string") {
      try {
        const payload = JSON.parse(
          Buffer.from(input.split(".")[1], "base64url").toString(),
        ) as Record<string, unknown>;
        return normalizeSubject(payload["credentialSubject"]);
      } catch {
        return {};
      }
    }

    return normalizeSubject(obj["credentialSubject"]);
  }

  if (format === "vc-jwt") {
    if (typeof input !== "string") return {};
    try {
      const payload = JSON.parse(
        Buffer.from(input.split(".")[1], "base64url").toString(),
      ) as Record<string, unknown>;
      const vc = payload["vc"] as Record<string, unknown> | undefined;
      return normalizeSubject(vc?.["credentialSubject"] ?? payload["credentialSubject"]);
    } catch {
      return {};
    }
  }

  if (format === "sd-jwt-vc") {
    if (typeof input !== "string") return {};
    try {
      // SD-JWT VC: issuer JWT is the first segment before ~
      const issuerJwt = input.split("~")[0];
      const payload = JSON.parse(
        Buffer.from(issuerJwt.split(".")[1], "base64url").toString(),
      ) as Record<string, unknown>;
      // In SD-JWT VC the subject may be directly in the payload or under credentialSubject
      return normalizeSubject(payload["credentialSubject"] ?? payload);
    } catch {
      return {};
    }
  }

  return {};
}

function normalizeSubject(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== "object") return {};
  if (Array.isArray(raw)) {
    // Multi-subject — take the first one
    return (raw[0] as Record<string, unknown>) ?? {};
  }
  return raw as Record<string, unknown>;
}

/**
 * Extract structured identity from a credentialSubject object.
 */
export function extractIdentity(
  subject: Record<string, unknown>,
): ExtractedIdentity {
  const identity: ExtractedIdentity = {
    additionalClaims: {},
  };

  // Subject ID
  if (typeof subject["id"] === "string") {
    identity.subjectId = subject["id"];
  }

  // Organization name — try each well-known field in priority order
  for (const field of ORG_NAME_FIELDS) {
    const value = findFieldValue(subject, field);
    if (value !== undefined) {
      identity.organizationName = String(value);
      break;
    }
  }

  // Organization identifier
  for (const field of ORG_IDENTIFIER_FIELDS) {
    const value = findFieldValue(subject, field);
    if (value !== undefined) {
      identity.organizationIdentifier = String(value);
      break;
    }
  }

  // Identifier type
  for (const field of IDENTIFIER_TYPE_FIELDS) {
    const value = findFieldValue(subject, field);
    if (value !== undefined) {
      identity.identifierType = String(value);
      break;
    }
  }

  // Jurisdiction — may be a string or nested object with a country field
  for (const field of JURISDICTION_FIELDS) {
    const value = findFieldValue(subject, field);
    if (value !== undefined) {
      if (typeof value === "string") {
        identity.jurisdiction = value;
      } else if (typeof value === "object" && value !== null) {
        // Nested address object — look for country inside
        const obj = value as Record<string, unknown>;
        const country = obj["country"] ?? obj["addressCountry"] ?? obj["countryName"];
        if (typeof country === "string") {
          identity.jurisdiction = country;
        }
      }
      break;
    }
  }

  // Infer identifier type from the identifier field name if not explicitly set
  if (identity.organizationIdentifier && !identity.identifierType) {
    identity.identifierType = inferIdentifierType(subject);
  }

  // Collect remaining claims that were not extracted into named fields
  for (const [key, value] of Object.entries(subject)) {
    if (!EXTRACTED_FIELD_NAMES.has(key)) {
      identity.additionalClaims[key] = value;
    }
  }

  return identity;
}

/**
 * Look up a field value, supporting both top-level and nested paths
 * (e.g., `organization.legalName`).
 */
function findFieldValue(
  subject: Record<string, unknown>,
  field: string,
): unknown {
  // Direct match
  if (subject[field] !== undefined && subject[field] !== null && subject[field] !== "") {
    return subject[field];
  }

  // Check inside common wrapper objects
  const wrappers = ["organization", "entity", "company", "registeredEntity"];
  for (const wrapper of wrappers) {
    const nested = subject[wrapper];
    if (nested && typeof nested === "object") {
      const obj = nested as Record<string, unknown>;
      if (obj[field] !== undefined && obj[field] !== null && obj[field] !== "") {
        return obj[field];
      }
    }
  }

  return undefined;
}

/**
 * Infer the identifier type from which field name matched.
 */
function inferIdentifierType(subject: Record<string, unknown>): string | undefined {
  const fieldTypeMap: Record<string, string> = {
    leiCode: "LEI",
    lei: "LEI",
    dunsNumber: "DUNS",
    registrationNumber: "CRN",
    companyNumber: "CRN",
    taxId: "TAX_ID",
    vatNumber: "VAT",
    globalLocationNumber: "GLN",
  };

  for (const [field, type] of Object.entries(fieldTypeMap)) {
    if (findFieldValue(subject, field) !== undefined) {
      return type;
    }
  }
  return undefined;
}
