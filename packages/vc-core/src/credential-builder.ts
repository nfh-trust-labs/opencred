import { randomUUID } from "node:crypto";
import { ValidationError } from "@opencred/shared";
import type {
  ContextEntry,
  CredentialSchema,
  CredentialStatus,
  CredentialSubject,
  Issuer,
  UnsignedCredential,
} from "./types.js";
import { W3C_CREDENTIALS_V2_CONTEXT, DATA_INTEGRITY_V1_CONTEXT } from "./types.js";

/**
 * Strict ISO 8601 datetime regex.
 * Accepts: YYYY-MM-DDTHH:mm:ssZ, YYYY-MM-DDTHH:mm:ss.sssZ,
 *          YYYY-MM-DDTHH:mm:ss+HH:MM, YYYY-MM-DDTHH:mm:ss-HH:MM
 */
const STRICT_ISO_8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function isStrictIso8601(value: string): boolean {
  if (!STRICT_ISO_8601.test(value)) return false;
  // Also verify it parses to a valid date (catches e.g. month 13)
  return !isNaN(Date.parse(value));
}

function isValidIssuerUri(id: string): boolean {
  return id.startsWith("did:") || id.startsWith("https://");
}

function isValidCredentialUri(id: string): boolean {
  return id.startsWith("urn:uuid:") || id.startsWith("https://");
}

/**
 * Fluent builder for constructing W3C VC Data Model 2.0 unsigned credentials.
 *
 * Usage:
 * ```ts
 * const vc = new CredentialBuilder()
 *   .setIssuer("did:web:university.example")
 *   .setCredentialSubject({ id: "did:example:holder456", name: "Jane Doe" })
 *   .setValidFrom("2026-02-09T00:00:00Z")
 *   .setValidUntil("2027-02-09T00:00:00Z")
 *   .setCredentialStatus({
 *     id: "https://dedi.global/dedi/lookup/university.example/vc-revocation-registry/<hash>",
 *     type: "dedi",
 *     statusPurpose: "revocation",
 *     statusListCredential: "https://dedi.global/dedi/query/university.example/vc-revocation-registry",
 *   })
 *   .build();
 * ```
 */
export class CredentialBuilder {
  private _contexts: ContextEntry[] = [W3C_CREDENTIALS_V2_CONTEXT];
  private _types: string[] = ["VerifiableCredential"];
  private _issuer: Issuer | undefined;
  private _credentialSubject: CredentialSubject | undefined;
  private _validFrom: string | undefined;
  private _validUntil: string | undefined;
  private _credentialStatus: CredentialStatus | undefined;
  private _credentialSchema: CredentialSchema | undefined;
  private _id: string | undefined;

  /**
   * Add a JSON-LD context entry. The base credentials/v2 context is always
   * included as the first entry and cannot be removed.
   *
   * Note: the credentials/v2 context subsumes data-integrity/v1, so adding
   * DATA_INTEGRITY_V1_CONTEXT is a no-op to avoid redundant context entries.
   */
  addContext(context: ContextEntry): this {
    if (context === W3C_CREDENTIALS_V2_CONTEXT) {
      return this; // Already included
    }
    // The W3C credentials/v2 context subsumes data-integrity/v1.
    // Adding both is redundant and may confuse JSON-LD processors.
    if (context === DATA_INTEGRITY_V1_CONTEXT) {
      return this;
    }
    if (!this._contexts.includes(context)) {
      this._contexts.push(context);
    }
    return this;
  }

  /** Add a credential type (e.g. "UniversityDegreeCredential"). */
  addType(type: string): this {
    if (!this._types.includes(type)) {
      this._types.push(type);
    }
    return this;
  }

  /** Set a custom credential ID. Must be a valid URI (urn:uuid: or https://). */
  setId(id: string): this {
    if (!isValidCredentialUri(id)) {
      throw new ValidationError(`Credential id must be a valid URI (urn:uuid: or https://): ${id}`);
    }
    this._id = id;
    return this;
  }

  /** Set the credential issuer (DID string or issuer object). */
  setIssuer(issuer: Issuer): this {
    const issuerId = typeof issuer === "string" ? issuer : issuer.id;
    if (!issuerId || issuerId.trim() === "") {
      throw new ValidationError(
        typeof issuer === "string"
          ? "Issuer cannot be an empty string"
          : "Issuer id cannot be empty",
      );
    }
    if (!isValidIssuerUri(issuerId)) {
      throw new ValidationError(`Issuer must be a valid URI (did: or https://): ${issuerId}`);
    }
    this._issuer = issuer;
    return this;
  }

  /** Set the credential subject containing claims. */
  setCredentialSubject(subject: CredentialSubject): this {
    this._credentialSubject = subject;
    return this;
  }

  /** Set the `validFrom` date (ISO 8601 string). */
  setValidFrom(date: string): this {
    if (!isStrictIso8601(date)) {
      throw new ValidationError(
        `Invalid validFrom date: ${date}. Must be ISO 8601 format (YYYY-MM-DDTHH:mm:ssZ or with timezone offset)`,
      );
    }
    this._validFrom = date;
    return this;
  }

  /** Set the `validUntil` date (ISO 8601 string). */
  setValidUntil(date: string): this {
    if (!isStrictIso8601(date)) {
      throw new ValidationError(
        `Invalid validUntil date: ${date}. Must be ISO 8601 format (YYYY-MM-DDTHH:mm:ssZ or with timezone offset)`,
      );
    }
    this._validUntil = date;
    return this;
  }

  /**
   * Set the credential status for revocation.
   * The `id` field must be a valid HTTPS URL (the DeDi revocation registry URL).
   */
  setCredentialStatus(status: CredentialStatus): this {
    this._credentialStatus = status;
    return this;
  }

  /** Set a credential schema reference. */
  setSchema(schema: CredentialSchema): this {
    this._credentialSchema = schema;
    return this;
  }

  /**
   * Build and return the unsigned credential.
   * Validates all required fields and invariants.
   *
   * @throws {ValidationError} if required fields are missing or invalid.
   */
  build(): UnsignedCredential {
    if (!this._issuer) {
      throw new ValidationError("Issuer is required");
    }

    if (!this._credentialSubject) {
      throw new ValidationError("Credential subject is required");
    }

    if (!this._validFrom) {
      throw new ValidationError("validFrom date is required");
    }

    // Validate validFrom is a strict ISO 8601 datetime
    if (!isStrictIso8601(this._validFrom)) {
      throw new ValidationError(
        `Invalid validFrom date: ${this._validFrom}. Must be ISO 8601 format (YYYY-MM-DDTHH:mm:ssZ or with timezone offset)`,
      );
    }

    // Validate validUntil if provided
    if (this._validUntil) {
      if (!isStrictIso8601(this._validUntil)) {
        throw new ValidationError(
          `Invalid validUntil date: ${this._validUntil}. Must be ISO 8601 format (YYYY-MM-DDTHH:mm:ssZ or with timezone offset)`,
        );
      }
      if (Date.parse(this._validUntil) <= Date.parse(this._validFrom)) {
        throw new ValidationError("validUntil must be after validFrom");
      }
    }

    // Validate credentialStatus.id is a valid HTTPS URL
    if (this._credentialStatus) {
      validateRevocationRegistryUrl(this._credentialStatus.id);
    }

    // Validate issuer format — must be a valid URI (did: or https://)
    const issuerId = typeof this._issuer === "string" ? this._issuer : this._issuer.id;
    if (!issuerId || issuerId.trim() === "") {
      throw new ValidationError(
        typeof this._issuer === "string"
          ? "Issuer cannot be an empty string"
          : "Issuer id cannot be empty",
      );
    }
    if (!isValidIssuerUri(issuerId)) {
      throw new ValidationError(`Issuer must be a valid URI (did: or https://): ${issuerId}`);
    }

    const credential: UnsignedCredential = {
      "@context": [...this._contexts],
      id: this._id ?? `urn:uuid:${randomUUID()}`,
      type: [...this._types],
      issuer: this._issuer,
      validFrom: this._validFrom,
      credentialSubject: structuredClone(this._credentialSubject),
    };

    if (this._validUntil) {
      credential.validUntil = this._validUntil;
    }

    if (this._credentialStatus) {
      credential.credentialStatus = { ...this._credentialStatus };
    }

    if (this._credentialSchema) {
      credential.credentialSchema = { ...this._credentialSchema };
    }

    return credential;
  }
}

/**
 * Validates that a revocation registry URL is a parseable HTTPS URL.
 * @throws {ValidationError} if the URL is invalid or not HTTPS.
 */
function validateRevocationRegistryUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ValidationError(`Invalid revocation registry URL: ${url}. Must be a valid URL.`);
  }

  if (parsed.protocol !== "https:") {
    throw new ValidationError(`Revocation registry URL must use HTTPS: ${url}`);
  }
}
