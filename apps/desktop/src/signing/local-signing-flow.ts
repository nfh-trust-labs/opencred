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

import * as crypto from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { CredentialBuilder } from "@opencred/vc-core";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import { createRegistry, Validator } from "@opencred/schema-engine";
import type { SchemaRegistry, ValidationResult } from "@opencred/schema-engine";
import { signWithFormat } from "./proof-format-router.js";
import type { UiProofFormat } from "../shared/ipc-types.js";
import { deriveVerificationMethod } from "./types.js";
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
  /** Proof format (default: "vc-jwt"). */
  proofFormat?: UiProofFormat;
  /** Field names for SD-JWT-VC selective disclosure. */
  selectiveDisclosureClaims?: string[];
  /** Optional credential schema URL (JSON Schema link in the VC). */
  credentialSchemaUrl?: string;
  /** Context URL for custom schemas (e.g., DeDi-published context). */
  contextUrl?: string;
  /** Inline JSON-LD context for custom schemas (auto-generated). */
  inlineContext?: Record<string, unknown>;
}

/**
 * Result of a local signing operation.
 */
export interface LocalSigningResult {
  /** The signed VC (JSON object) or compact token string (SD-JWT-VC). */
  credential: VerifiableCredential | string;
  /** The unsigned credential (for reference). */
  unsignedCredential: UnsignedCredential;
  /** The proof format used. */
  proofFormat: string;
  /** True when credential is a compact token (SD-JWT-VC). */
  isCompactToken: boolean;
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

  // Add JSON-LD context for Data Integrity proofs (required for RDFC-1.0 canonicalization).
  // VC-JWT and SD-JWT-VC don't need this — fields are preserved as-is in the JWT payload.
  const proofFormat = options.proofFormat ?? "vc-jwt";
  if (proofFormat === "data-integrity") {
    // Priority: built-in schema URL > DeDi URL > inline context
    const builtInContextUrl = getRegistry().getContextForType(options.schemaId);
    if (builtInContextUrl) {
      builder.addContext(builtInContextUrl);
    } else if (options.contextUrl) {
      builder.addContext(options.contextUrl);
    } else if (options.inlineContext) {
      builder.addContext(options.inlineContext);
    }
  }

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

  // Set revocation status — pre-generate credential UUID so the hashed ID
  // can be embedded in the credentialStatus lookup URL.
  if (options.revocationRegistryUrl) {
    const credentialUuid = crypto.randomUUID();
    const credentialId = `urn:uuid:${credentialUuid}`;
    builder.setId(credentialId);

    const revocationHash = crypto
      .createHash("sha256")
      .update(credentialUuid)
      .digest("hex");
    const statusListCredential = options.revocationRegistryUrl;
    const lookupUrl = statusListCredential.replace("/dedi/query/", "/dedi/lookup/");
    builder.setCredentialStatus({
      id: `${lookupUrl}/${revocationHash}`,
      type: "dedi",
      statusPurpose: "revocation",
      statusListCredential,
    });
  }

  // Set credential schema link.
  //
  // Per W3C VCDM 2.0, every issued credential SHOULD carry a `credentialSchema`
  // field referencing the JSON Schema it conforms to. We populate this for
  // every built-in schema using the priority:
  //   1. user-provided `credentialSchemaUrl` (e.g. an upgraded permanent URL)
  //   2. the schema's own `$id` (the placeholder URL on built-in schemas —
  //      issuers can update this later by passing `credentialSchemaUrl`)
  //
  // Custom (inline) schemas use a separate path in handleBuildAndSign which
  // also handles the data-URI fallback.
  const credentialSchemaIdFromBuiltIn = (() => {
    if (options.credentialSchemaUrl) {
      return options.credentialSchemaUrl;
    }
    try {
      const def = getRegistry().getSchema(options.schemaId);
      const id = (def.schema as { $id?: unknown }).$id;
      return typeof id === "string" && id.length > 0 ? id : undefined;
    } catch {
      return undefined;
    }
  })();

  if (credentialSchemaIdFromBuiltIn) {
    builder.setSchema({ id: credentialSchemaIdFromBuiltIn, type: "JsonSchema" });
  }

  const unsignedCredential = builder.build();

  // Step 3–5: Sign using the proof format router
  const format = proofFormat;

  // Derive vct for SD-JWT-VC from additional types or schema ID
  const vct =
    options.additionalTypes?.[0] ?? options.schemaId;

  // For did:web issuers, the verificationMethod in the proof should use the
  // did:web DID's verification method ID, not the signer's did:key-based ID
  const verificationMethod = deriveVerificationMethod(options.issuerDid, signer.id);

  let signedOutput: string;
  let isCompactToken: boolean;

  // Custom JSON-LD contexts are served by the shared document loader from
  // a per-URL cache populated at schema-save time. Conflicts on the same
  // URL are rejected at save time by content-hash comparison (see
  // `handleCustomSchemaSave`), so canonicalization can rely on the
  // URL → document mapping being stable without per-schema scoping.
  try {
    const result = await signWithFormat(signer, unsignedCredential, format, {
      verificationMethod,
      selectiveDisclosureClaims: options.selectiveDisclosureClaims,
      vct,
    });
    signedOutput = result.signedOutput;
    isCompactToken = result.isCompactToken;
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError(
      `Local signing failed: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }

  // Step 6: For JSON-based proofs (vc-jwt, data-integrity), embed trust chain metadata
  if (!isCompactToken) {
    const signedCredential = JSON.parse(signedOutput) as VerifiableCredential;

    // Embed X.509 certificate chain in proof if the signer has one.
    if (signer.metadata.certificateChain && signer.metadata.certificateChain.length > 0) {
      const proof = signedCredential.proof as Record<string, unknown>;
      proof.x5c = signer.metadata.certificateChain.map(pemToBase64Der);
    }


    signedOutput = JSON.stringify(signedCredential);
  }

  // For compact tokens (SD-JWT-VC), return the compact string directly
  const credential: VerifiableCredential | string = isCompactToken
    ? signedOutput
    : (JSON.parse(signedOutput) as VerifiableCredential);

  return {
    credential,
    unsignedCredential,
    proofFormat: format,
    isCompactToken,
  };
}
