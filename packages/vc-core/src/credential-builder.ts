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
 * Validate that a `credentialSubject.id` is one of the allowed URI schemes.
 *
 * Accepts:
 * - `did:*` — any DID (e.g., `did:web:`, `did:key:`, `did:jwk:`).
 * - `urn:uuid:*` — UUID URN.
 * - `https://*` — HTTPS URL.
 *
 * Rejects every other scheme (`javascript:`, `data:`, `file:`, `http:`, etc.)
 * and any non-URI string. Used for defense-in-depth against subject-id
 * injection at the library boundary.
 */
export function isValidSubjectUri(id: string): boolean {
  return id.startsWith("did:") || id.startsWith("urn:uuid:") || id.startsWith("https://");
}

/**
 * Maximum allowed validity window (years) between `validFrom` and `validUntil`.
 *
 * Default is 10 years; overridable at build time via the
 * `OPENCRED_MAX_VALIDITY_YEARS` environment variable. Unset or invalid
 * values fall back to the default so that misconfiguration cannot weaken
 * the ceiling.
 */
const DEFAULT_MAX_VALIDITY_YEARS = 10;

function resolveMaxValidityYears(): number {
  const raw = process.env.OPENCRED_MAX_VALIDITY_YEARS;
  if (raw === undefined || raw === "") {
    return DEFAULT_MAX_VALIDITY_YEARS;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_MAX_VALIDITY_YEARS;
  }
  return parsed;
}

/**
 * Truncate a potentially-huge user-supplied string for inclusion in error
 * messages. Keeps error output bounded so a large input doesn't balloon
 * log entries or leak excessive context.
 */
function truncateForError(value: string, max = 80): string {
  return value.length > max ? `${value.slice(0, max)}...` : value;
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

  /**
   * Set the credential subject containing claims.
   *
   * If `subject.id` is provided it MUST be one of the allowed URI schemes:
   * `did:*`, `urn:uuid:*`, or `https://*`. Empty strings, non-string values,
   * and any other scheme (e.g. `javascript:`, `data:`, `http:`, file paths,
   * or plain identifiers) are rejected. This guards callers (server routes,
   * IPC handlers, CSV importers) that forward user input without
   * schema-level validation.
   */
  setCredentialSubject(subject: CredentialSubject): this {
    if (subject && "id" in subject && subject.id !== undefined) {
      const rawId: unknown = subject.id;
      if (typeof rawId !== "string") {
        throw new ValidationError(`credentialSubject.id must be a string, got ${typeof rawId}`);
      }
      if (rawId.trim() === "") {
        throw new ValidationError("credentialSubject.id must be a non-empty string");
      }
      if (!isValidSubjectUri(rawId)) {
        throw new ValidationError(
          `credentialSubject.id must be a valid URI (did:, urn:uuid:, or https://): ${truncateForError(rawId)}`,
        );
      }
    }
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
      const validUntilMs = Date.parse(this._validUntil);
      const validFromMs = Date.parse(this._validFrom);
      // Must be strictly after validFrom (rejects equal or earlier).
      if (validUntilMs <= validFromMs) {
        throw new ValidationError("validUntil must be after validFrom");
      }
      // Enforce an upper bound on the validity window to prevent long-lived
      // credentials from being issued by mistake or abuse. The window is
      // measured from `validFrom` (always set at this point; required above).
      const maxYears = resolveMaxValidityYears();
      const maxWindowMs = maxYears * 365.25 * 24 * 3600 * 1000;
      if (validUntilMs - validFromMs > maxWindowMs) {
        throw new ValidationError(
          `validUntil exceeds maximum allowed validity window of ${maxYears} year(s). ` +
            `Attempted validFrom=${this._validFrom}, validUntil=${this._validUntil}.`,
        );
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
