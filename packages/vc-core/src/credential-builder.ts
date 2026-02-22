import { v4 as uuidv4 } from "uuid";
import { ValidationError } from "@opencred/shared";
import type {
  ContextEntry,
  CredentialSchema,
  CredentialStatus,
  CredentialSubject,
  Issuer,
  UnsignedCredential,
} from "./types.js";
import { W3C_CREDENTIALS_V2_CONTEXT } from "./types.js";

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
 *     id: "https://dedi.example/revocations/university.example/revocation-registry",
 *     type: "DeDiRevocationListStatusV1",
 *     statusPurpose: "revocation",
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
   */
  addContext(context: ContextEntry): this {
    if (context === W3C_CREDENTIALS_V2_CONTEXT) {
      return this; // Already included
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

  /** Set a custom credential ID. If not called, a `urn:uuid:*` ID is generated. */
  setId(id: string): this {
    this._id = id;
    return this;
  }

  /** Set the credential issuer (DID string or issuer object). */
  setIssuer(issuer: Issuer): this {
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
    this._validFrom = date;
    return this;
  }

  /** Set the `validUntil` date (ISO 8601 string). */
  setValidUntil(date: string): this {
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

    // Validate validFrom is a parseable date
    if (isNaN(Date.parse(this._validFrom))) {
      throw new ValidationError(`Invalid validFrom date: ${this._validFrom}`);
    }

    // Validate validUntil if provided
    if (this._validUntil) {
      if (isNaN(Date.parse(this._validUntil))) {
        throw new ValidationError(`Invalid validUntil date: ${this._validUntil}`);
      }
      if (Date.parse(this._validUntil) <= Date.parse(this._validFrom)) {
        throw new ValidationError("validUntil must be after validFrom");
      }
    }

    // Validate credentialStatus.id is a valid HTTPS URL
    if (this._credentialStatus) {
      validateRevocationRegistryUrl(this._credentialStatus.id);
    }

    // Validate issuer format
    if (typeof this._issuer === "string" && this._issuer.trim() === "") {
      throw new ValidationError("Issuer cannot be an empty string");
    }
    if (typeof this._issuer === "object" && (!this._issuer.id || this._issuer.id.trim() === "")) {
      throw new ValidationError("Issuer id cannot be empty");
    }

    const credential: UnsignedCredential = {
      "@context": [...this._contexts],
      id: this._id ?? `urn:uuid:${uuidv4()}`,
      type: [...this._types],
      issuer: this._issuer,
      validFrom: this._validFrom,
      credentialSubject: { ...this._credentialSubject },
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
