/**
 * Local signing flow for the OpenCred desktop app.
 *
 * Orchestrates the complete offline VC issuance pipeline:
 *   1. Validate payload against schema (using @opencred/schema-engine)
 *   2. Build unsigned VC (using CredentialBuilder from @opencred/vc-core)
 *   3. Prepare proof (using prepareProof from @opencred/crypto)
 *   4. Sign with the software signer
 *   5. Complete proof (using completeProof from @opencred/crypto)
 *   6. Return the signed VerifiableCredential
 *
 * All of this works OFFLINE -- no network needed. JSON-LD contexts
 * are bundled and loaded locally.
 *
 * SECURITY INVARIANTS:
 *  - The private key never leaves the issuer's machine.
 *  - Key material is NEVER logged.
 *  - No network requests are made during signing.
 */

import { CryptoError } from "@opencred/shared";
import { prepareProof, completeProof } from "@opencred/crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import { createRegistry, Validator } from "@opencred/schema-engine";
import type { SchemaRegistry, ValidationResult } from "@opencred/schema-engine";
import { getAttestation } from "../main/attestation-store.js";
import type { Signer } from "./types.js";

/**
 * Convert a PEM-encoded certificate to base64-encoded DER (for x5c).
 * Strips the PEM header/footer and joins all lines.
 */
function pemToBase64Der(pem: string): string {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s/g, "");
}

/**
 * Options for building and signing a credential.
 */
export interface LocalSigningOptions {
  /** The schema ID to validate the credential subject against. */
  schemaId: string;
  /** The issuer DID (e.g., "did:web:university.example"). */
  issuerDid: string;
  /** The credential subject containing claims. */
  credentialSubject: Record<string, unknown>;
  /** ISO 8601 date string for when the credential becomes valid. */
  validFrom: string;
  /** ISO 8601 date string for when the credential expires (optional). */
  validUntil?: string;
  /** Optional revocation registry URL (must be HTTPS). */
  revocationRegistryUrl?: string;
  /** Optional additional credential types (e.g., "UniversityDegreeCredential"). */
  additionalTypes?: string[];
  /** Optional subject DID. */
  subjectDid?: string;
}

/**
 * Result of a local signing operation.
 */
export interface LocalSigningResult {
  /** The signed Verifiable Credential. */
  credential: VerifiableCredential;
  /** The unsigned credential (for reference). */
  unsignedCredential: UnsignedCredential;
}

// Singleton registry -- created once and reused
let registryInstance: SchemaRegistry | null = null;
let validatorInstance: Validator | null = null;

function getRegistry(): SchemaRegistry {
  if (!registryInstance) {
    registryInstance = createRegistry();
  }
  return registryInstance;
}

function getValidator(): Validator {
  if (!validatorInstance) {
    validatorInstance = new Validator(getRegistry());
  }
  return validatorInstance;
}

/**
 * List all available schema IDs.
 */
export function listSchemas(): string[] {
  return getRegistry().listSchemas();
}

/**
 * Get a schema definition by ID.
 */
export function getSchemaDefinition(schemaId: string): {
  id: string;
  schema: Record<string, unknown>;
  contextUrl?: string;
} {
  return getRegistry().getSchema(schemaId);
}

/**
 * Validate credential subject data against a schema.
 */
export function validateSubject(schemaId: string, data: unknown): ValidationResult {
  return getValidator().validateCredentialSubject(schemaId, data);
}

/**
 * Build and sign a Verifiable Credential locally.
 *
 * This is the main entry point for local (offline) credential issuance.
 * It validates the payload, builds the unsigned VC, prepares the proof,
 * signs with the provided signer, and returns the complete VC.
 *
 * @param signer - The Signer instance to use for signing.
 * @param options - The credential building options.
 * @returns The signed VerifiableCredential and the unsigned VC for reference.
 * @throws {CryptoError} if signing fails.
 * @throws {ValidationError} if the credential subject fails schema validation.
 * @throws {SchemaValidationError} if the schema validation produces field errors.
 */
export async function buildAndSign(
  signer: Signer,
  options: LocalSigningOptions,
): Promise<LocalSigningResult> {
  // Step 1: Validate payload against schema
  getValidator().validateOrThrow(options.schemaId, options.credentialSubject);

  // Step 2: Build unsigned VC
  const builder = new CredentialBuilder()
    .setIssuer(options.issuerDid)
    .setValidFrom(options.validFrom);

  // Set credential subject
  const subject: Record<string, unknown> = { ...options.credentialSubject };
  if (options.subjectDid) {
    subject["id"] = options.subjectDid;
  }
  builder.setCredentialSubject(subject);

  // NOTE: Schema context URLs (e.g., https://opencred.dev/contexts/education/v1)
  // are NOT added to the credential's @context because they are not bundled
  // in the document loader. The bundled loader only supports W3C standard
  // contexts (credentials/v2, data-integrity/v1, delegation/v1). Adding
  // unbundled context URLs would cause JSON-LD canonicalization to fail
  // at signing time. The credential subject properties are still valid —
  // they just aren't mapped to a custom JSON-LD vocabulary.

  // Add additional types
  if (options.additionalTypes) {
    for (const type of options.additionalTypes) {
      builder.addType(type);
    }
  }

  // Set expiration
  if (options.validUntil) {
    builder.setValidUntil(options.validUntil);
  }

  // Set revocation status
  if (options.revocationRegistryUrl) {
    builder.setCredentialStatus({
      id: options.revocationRegistryUrl,
      type: "DeDiRevocationListStatusV1",
      statusPurpose: "revocation",
    });
  }

  const unsignedCredential = builder.build();

  // Step 3: Prepare proof
  const { dataToSign, proofConfig } = await prepareProof(unsignedCredential, {
    verificationMethod: signer.id,
    proofPurpose: "assertionMethod",
  });

  // Step 4: Sign with the software signer
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = await signer.sign(dataToSign);
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Local signing failed: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }

  // Validate signature length (P-256 raw r||s must be 64 bytes)
  if (signatureBytes.length !== 64) {
    throw new CryptoError(
      `Invalid signature length: expected 64 bytes, got ${signatureBytes.length}`,
    );
  }

  // Step 5: Complete proof
  const signedCredential = completeProof(unsignedCredential, proofConfig, signatureBytes);

  // Step 6: Embed X.509 certificate chain in proof if the signer has one.
  // This allows verifiers to trace the trust chain: VC → issuer key → DSC → CSCA.
  // The x5c field follows JOSE conventions (RFC 7517 §4.7): an array of
  // base64-encoded DER certificates, leaf (DSC) first.
  if (signer.metadata.certificateChain && signer.metadata.certificateChain.length > 0) {
    const proof = signedCredential.proof as Record<string, unknown>;
    proof.x5c = signer.metadata.certificateChain.map(pemToBase64Der);
  }

  // Step 7: Embed attestation VC in proof if the signing key has one
  const attestation = getAttestation(signer.id);
  if (attestation) {
    const proof = signedCredential.proof as Record<string, unknown>;
    proof.keyAttestationCredential = attestation.credential;
  }

  return {
    credential: signedCredential,
    unsignedCredential,
  };
}
