/**
 * Credential issuance and verification endpoints.
 *
 * POST /credentials/issue  — build, validate, and sign a Verifiable Credential
 * POST /credentials/verify — verify a signed Verifiable Credential
 *
 * Follows the same patterns as the desktop local-signing-flow.
 *
 * SECURITY INVARIANTS:
 *  - The signing key is loaded at startup from a local file — never from requests.
 *  - Key material is NEVER logged or returned in responses.
 *  - JSON-LD contexts are bundled — no remote fetching.
 */

import { randomUUID, createHash } from "node:crypto";
import { Hono } from "hono";
import { z } from "zod";
import { CredentialBuilder, isValidSubjectUri } from "@opencred/vc-core";
import type { VerifiableCredential } from "@opencred/vc-core";
import { Validator } from "@opencred/schema-engine";
import type { SchemaRegistry } from "@opencred/schema-engine";
import { getSchemaRegistry } from "../schema-registry-singleton.js";
import {
  prepareVcJwtProof,
  completeVcJwtProof,
  prepareProof,
  completeProof,
  prepareEdDsaProof,
  completeEdDsaProof,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
} from "@opencred/crypto";
import { CryptoError, ValidationError, detectCredentialInputFormat } from "@opencred/shared";
import type { TemplateCustomization } from "@opencred/templates";
import { requireSigner } from "../signing/key-manager.js";
import { packageCredential } from "../packaging/packager.js";
import type { PackageFormat } from "../packaging/packager.js";
import { credentialsIssuedTotal, credentialsVerifiedTotal } from "../metrics.js";

const credentials = new Hono();

/**
 * Zod schema for issuer branding customization. Only data URIs are accepted
 * for logos — never remote URLs (prevents SSRF). See CLAUDE.md rule 7.
 */
export const customizationSchema = z
  .object({
    primaryColor: z
      .string()
      .regex(/^#[0-9a-fA-F]{6}$/, "6-digit hex color required")
      .optional(),
    backgroundColor: z
      .string()
      .regex(/^#[0-9a-fA-F]{6}$/, "6-digit hex color required")
      .optional(),
    secondaryColor: z
      .string()
      .regex(/^#[0-9a-fA-F]{6}$/, "6-digit hex color required")
      .optional(),
    textColor: z
      .string()
      .regex(/^#[0-9a-fA-F]{6}$/, "6-digit hex color required")
      .optional(),
    labelColor: z
      .string()
      .regex(/^#[0-9a-fA-F]{6}$/, "6-digit hex color required")
      .optional(),
    logoDataUri: z
      .string()
      .startsWith("data:image/", "Must be data URI")
      .optional(),
    logoWidth: z.number().int().min(10).max(200).optional(),
    logoHeight: z.number().int().min(10).max(200).optional(),
    footerText: z.string().max(500).optional(),
    sealDataUri: z
      .string()
      .startsWith("data:image/", "Must be data URI")
      .optional(),
    issuerDisplayName: z.string().max(200).optional(),
  })
  .optional();

/**
 * Hard-coded list of fields that MUST NOT appear in any request body.
 * The OpenCred server NEVER accepts private key material via the HTTP API —
 * keys are loaded once at startup from the local filesystem (or a configured
 * Cloud HSM provider). Any request that smuggles in a private key (or even
 * a string that looks like one) is rejected with a 400.
 */
const FORBIDDEN_REQUEST_KEYS = new Set([
  "privateKey",
  "private_key",
  "privateKeyJwk",
  "private_key_jwk",
  "privateKeyPem",
  "private_key_pem",
  "pkcs8",
  "pkcs12",
  "pfx",
  "p12",
  "keyMaterial",
  "key_material",
]);

/**
 * Regular expression matching any PEM private key header. Covers all common
 * encodings the OpenSSL toolchain produces by default:
 *
 *   -----BEGIN PRIVATE KEY-----            PKCS#8 (unencrypted)
 *   -----BEGIN ENCRYPTED PRIVATE KEY-----  PKCS#8 (encrypted, RFC 5958)
 *   -----BEGIN RSA PRIVATE KEY-----        PKCS#1 RSA (openssl genrsa default)
 *   -----BEGIN EC PRIVATE KEY-----         SEC1 EC (openssl ecparam -genkey default)
 *   -----BEGIN DSA PRIVATE KEY-----        OpenSSL DSA
 *   -----BEGIN OPENSSH PRIVATE KEY-----    OpenSSH
 *
 * The previous substring check `"BEGIN PRIVATE KEY"` only matched the PKCS#8
 * unencrypted form — an attacker or misconfigured client submitting any of
 * the other formats slipped through. See CLAUDE.md rule 1.
 */
const PEM_PRIVATE_KEY_RE = /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/;

/**
 * Recursively walk an unknown JSON value and throw a ValidationError if any
 * key in {@link FORBIDDEN_REQUEST_KEYS} is present, OR if any string value
 * looks like a PEM-encoded private key.
 *
 * This is a defense-in-depth check on top of Zod's schema parsing — Zod
 * silently drops unknown fields, but we want a loud, audited rejection so
 * misconfigured clients learn fast and never accidentally upload key material.
 *
 * Exported so every route that accepts a JSON body (issue, verify, batch,
 * revocation, packaging) applies the same guard — there must never be a
 * "back door" route that forgets to call this. See CLAUDE.md rule 1.
 */
export function rejectKeyMaterial(value: unknown, path = ""): void {
  if (value === null || typeof value !== "object") {
    if (typeof value === "string" && PEM_PRIVATE_KEY_RE.test(value)) {
      throw new ValidationError(
        `Request rejected: field at "${path || "<root>"}" looks like a PEM-encoded private key. ` +
          "OpenCred never accepts private key material via the HTTP API.",
      );
    }
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      rejectKeyMaterial(item, `${path}[${String(index)}]`);
    });
    return;
  }

  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_REQUEST_KEYS.has(key)) {
      throw new ValidationError(
        `Request rejected: field "${key}" is forbidden. ` +
          "OpenCred never accepts private key material via the HTTP API.",
      );
    }
    rejectKeyMaterial(child, path ? `${path}.${key}` : key);
  }
}

let validatorInstance: Validator | null = null;

function getRegistry(): SchemaRegistry {
  return getSchemaRegistry();
}

function getValidator(): Validator {
  if (!validatorInstance) {
    validatorInstance = new Validator(getRegistry());
  }
  return validatorInstance;
}

// --- Request schemas ---

const issueRequestSchema = z.object({
  schemaId: z.string(),
  issuerDid: z.string(),
  credentialSubject: z.record(z.unknown()),
  validFrom: z.string(),
  validUntil: z.string().optional(),
  proofFormat: z.enum(["vc-jwt", "data-integrity", "sd-jwt-vc"]).default("vc-jwt"),
  additionalTypes: z.array(z.string()).optional(),
  // HIGH-02: reject `credentialSubject.id` values whose URI scheme is not
  // one of `did:*`, `urn:uuid:*`, or `https://*` before they reach the
  // builder. `CredentialBuilder.setCredentialSubject()` enforces the same
  // rule post-#A (defense in depth) but doing it here returns a clearer
  // Zod-formatted error with a stable path instead of a generic 500.
  subjectDid: z
    .string()
    .refine(isValidSubjectUri, {
      message: "subjectDid must be a valid DID (did:*), urn:uuid, or https:// URI",
    })
    .optional(),
  selectiveDisclosureClaims: z.array(z.string()).optional(),
  revocationRegistryUrl: z.string().url().optional(),
  credentialSchemaUrl: z.string().url().optional(),
  packageFormats: z
    .array(z.enum(["qr-png", "qr-svg", "pdf", "json", "json-compact"]))
    .optional(),
  customization: customizationSchema,
});

const verifyRequestSchema = z.object({
  credential: z.string(),
});

// --- Issue endpoint ---

credentials.post("/credentials/issue", async (c) => {
  const body = await c.req.json();
  // SECURITY: reject any request that contains private key material BEFORE
  // we even look at the schema. See FORBIDDEN_REQUEST_KEYS above.
  rejectKeyMaterial(body);
  const parsed = issueRequestSchema.parse(body);
  const signer = requireSigner();

  // Validate credential subject against schema
  getValidator().validateOrThrow(parsed.schemaId, parsed.credentialSubject);

  // Build unsigned credential
  const builder = new CredentialBuilder()
    .setIssuer(parsed.issuerDid)
    .setValidFrom(parsed.validFrom);

  const subject: Record<string, unknown> = { ...parsed.credentialSubject };
  if (parsed.subjectDid) {
    subject["id"] = parsed.subjectDid;
  }
  builder.setCredentialSubject(subject);

  // Add JSON-LD context for Data Integrity proofs (required for RDFC-1.0
  // canonicalization with safe mode). VC-JWT and SD-JWT-VC don't need this —
  // fields are preserved as-is in the JWT payload.
  if (parsed.proofFormat === "data-integrity") {
    const builtInContextUrl = getRegistry().getContextForType(parsed.schemaId);
    if (builtInContextUrl) {
      builder.addContext(builtInContextUrl);
    }
  }

  if (parsed.additionalTypes) {
    for (const type of parsed.additionalTypes) {
      builder.addType(type);
    }
  }
  if (parsed.validUntil) {
    builder.setValidUntil(parsed.validUntil);
  }
  if (parsed.revocationRegistryUrl) {
    const credentialUuid = randomUUID();
    builder.setId(`urn:uuid:${credentialUuid}`);
    const revocationHash = createHash("sha256").update(credentialUuid).digest("hex");
    const statusListCredential = parsed.revocationRegistryUrl;
    const lookupUrl = statusListCredential.replace("/dedi/query/", "/dedi/lookup/");
    builder.setCredentialStatus({
      id: `${lookupUrl}/${revocationHash}`,
      type: "dedi",
      statusPurpose: "revocation",
      statusListCredential,
    });
  }
  // Set credentialSchema link. Per W3C VCDM 2.0 §4.10, every issued
  // credential SHOULD reference the JSON Schema it conforms to. Priority
  // mirrors the desktop path (see `apps/desktop/src/signing/local-signing-flow.ts`
  // and `apps/desktop/src/main/ipc-handlers.ts handleBuildAndSign`):
  //   1. explicit credentialSchemaUrl from the request
  //   2. the schema's own `$id` when it has one
  //   3. a data-URI containing the base64-encoded schema as a last resort,
  //      so the credential is never silently shipped without a schema
  //      reference.
  const credentialSchemaId = ((): string => {
    if (parsed.credentialSchemaUrl) {
      return parsed.credentialSchemaUrl;
    }
    let schemaObject: Record<string, unknown> = {};
    try {
      const def = getRegistry().getSchema(parsed.schemaId);
      schemaObject = def.schema as Record<string, unknown>;
      const id = (schemaObject as { $id?: unknown }).$id;
      if (typeof id === "string" && id.length > 0) {
        return id;
      }
    } catch {
      // Schema not in the registry (e.g. inline/custom). Fall through to
      // the data-URI fallback with whatever we have — an empty object is
      // still a well-formed JSON Schema document.
    }
    const base64 = Buffer.from(JSON.stringify(schemaObject), "utf8").toString("base64");
    return `data:application/schema+json;base64,${base64}`;
  })();
  builder.setSchema({ id: credentialSchemaId, type: "JsonSchema" });

  const unsigned = builder.build();

  // Sign based on proof format
  const proofFormat = parsed.proofFormat;
  const vct = parsed.additionalTypes?.[0] ?? parsed.schemaId;

  let signedOutput: string;
  let isCompactToken = false;

  switch (proofFormat) {
    case "vc-jwt": {
      const vcAsRecord = unsigned as unknown as Record<string, unknown>;
      const { signingInput } = prepareVcJwtProof(vcAsRecord, signer.algorithm, {
        verificationMethod: signer.id,
      });
      const dataToSign = new TextEncoder().encode(signingInput);
      const signatureBytes = await signer.sign(dataToSign);
      const jwt = completeVcJwtProof(signingInput, signatureBytes);

      const signedCredential = {
        ...unsigned,
        proof: { type: "JsonWebSignature2020", jwt },
      };
      signedOutput = JSON.stringify(signedCredential);
      break;
    }

    case "data-integrity": {
      if (signer.algorithm.startsWith("RSA")) {
        throw new CryptoError(
          "Data Integrity proofs are not supported with RSA keys. Use vc-jwt or sd-jwt-vc.",
        );
      }

      const proofOptions = {
        verificationMethod: signer.id,
        proofPurpose: "assertionMethod",
      };

      let signedCredential: VerifiableCredential;

      if (signer.algorithm === "Ed25519") {
        const { dataToSign, proofConfig } = await prepareEdDsaProof(unsigned, proofOptions);
        const signatureBytes = await signer.sign(dataToSign);
        signedCredential = completeEdDsaProof(unsigned, proofConfig, signatureBytes);
      } else {
        const { dataToSign, proofConfig } = await prepareProof(
          unsigned,
          proofOptions,
          signer.algorithm as "P-256" | "P-384",
        );
        const signatureBytes = await signer.sign(dataToSign);
        signedCredential = completeProof(unsigned, proofConfig, signatureBytes);
      }

      signedOutput = JSON.stringify(signedCredential);
      break;
    }

    case "sd-jwt-vc": {
      const sdJwtOptions = {
        selectiveDisclosureClaims: parsed.selectiveDisclosureClaims ?? [],
        vct,
        verificationMethod: signer.id,
      };

      const { signingInput, disclosures } = prepareSdJwtVcProof(
        unsigned,
        signer.algorithm,
        sdJwtOptions,
      );
      const dataToSign = new TextEncoder().encode(signingInput);
      const signatureBytes = await signer.sign(dataToSign);
      signedOutput = completeSdJwtVcProof(signingInput, signatureBytes, disclosures);
      isCompactToken = true;
      break;
    }

    default: {
      // Exhaustiveness guard: if Zod's proofFormat enum is widened without
      // updating this switch, fail loudly instead of returning a response
      // body where `signedOutput` is undefined.
      const _exhaustive: never = proofFormat;
      throw new CryptoError(`Unsupported proofFormat: ${String(_exhaustive)}`);
    }
  }

  // Package if formats requested (only for JSON-based credentials, not compact tokens)
  let packagedOutputs:
    | Array<{
        format: string;
        data: string;
        mimeType: string;
        suggestedFileName: string;
        encoding: string;
      }>
    | undefined;
  if (!isCompactToken && parsed.packageFormats && parsed.packageFormats.length > 0) {
    const credential = JSON.parse(signedOutput) as Parameters<typeof packageCredential>[0];
    const customization = parsed.customization as TemplateCustomization | undefined;
    const result = await packageCredential(credential, parsed.packageFormats as PackageFormat[], {
      customization,
    });
    packagedOutputs = result.outputs.map((output) => ({
      format: output.format,
      data: Buffer.isBuffer(output.data) ? output.data.toString("base64") : output.data,
      mimeType: output.mimeType,
      suggestedFileName: output.suggestedFileName,
      encoding: Buffer.isBuffer(output.data) ? "base64" : "utf-8",
    }));
  }

  credentialsIssuedTotal.inc({ proof_format: proofFormat, schema_id: parsed.schemaId });

  return c.json({
    credential: isCompactToken ? signedOutput : JSON.parse(signedOutput),
    proofFormat,
    isCompactToken,
    packagedOutputs,
  });
});

// --- Verify endpoint ---

/**
 * Sanitize a verification result for inclusion in an HTTP response.
 *
 * SECURITY: Per CLAUDE.md invariant #5 ("No secrets in error responses"), the
 * server response MUST NOT include the raw `detail` strings produced by the
 * verification engine. Those strings are intended for trusted, local callers
 * (e.g. the desktop client where the user owns both sides) and may contain:
 *   - the operator's CSCA trust anchor subject DN (internal config);
 *   - underlying X.509 / crypto parser error messages;
 *   - file-system or path-shaped state strings.
 *
 * An unauthenticated remote caller to /credentials/verify has no business
 * seeing any of that. We drop `detail` entirely and expose only the stable
 * `name` + `passed` fields, plus the top-level `code` enum which already has
 * a fixed vocabulary (VALID / REVOKED / EXPIRED / INVALID / UNRESOLVABLE /
 * CONTEXT_MISSING) suitable for external consumption.
 *
 * This helper is scoped to the server route. The desktop IPC handler returns
 * the full result shape (with `detail`) — desktop users have full trust and
 * need the extra context to debug failures.
 *
 * Exported only for unit testing — do not import from elsewhere in the
 * server. The contract is "strip detail", not "reformat checks".
 */
export function sanitizeChecksForServerResponse(
  checks: ReadonlyArray<{ name: string; passed: boolean; detail?: string }>,
): Array<{ name: string; passed: boolean }> {
  return checks.map(({ name, passed }) => ({ name, passed }));
}

/**
 * Build the sanitized verify-endpoint response body from a raw verification
 * result. Extracted so unit tests can drive it without spinning up the full
 * route — see the "response sanitization" block in `endpoints.test.ts`.
 *
 * SECURITY: see `sanitizeChecksForServerResponse` above.
 */
export function buildVerifyResponseBody(result: {
  verified: boolean;
  code: string;
  checks: ReadonlyArray<{ name: string; passed: boolean; detail?: string }>;
}): {
  valid: boolean;
  code: string;
  message: string;
  checks: Array<{ name: string; passed: boolean }>;
} {
  return {
    valid: result.verified,
    code: result.code,
    message: result.verified ? "Credential is valid." : "Verification failed.",
    checks: sanitizeChecksForServerResponse(result.checks),
  };
}

credentials.post("/credentials/verify", async (c) => {
  const body = await c.req.json();
  // SECURITY: even verify requests must not contain private key material.
  rejectKeyMaterial(body);
  const parsed = verifyRequestSchema.parse(body);

  const format = detectCredentialInputFormat(parsed.credential);

  let credential: Record<string, unknown> | string;
  switch (format) {
    case "pixelpass": {
      const { decodeQrData } = await import("../packaging/qr-generator.js");
      const decodedJson = decodeQrData(parsed.credential);
      credential = JSON.parse(decodedJson);
      break;
    }
    case "json":
      credential = JSON.parse(parsed.credential);
      break;
    case "jwt-compact":
      // Pass raw compact string — the verification engine's detectFormat()
      // already handles VC-JWT and SD-JWT compact serializations.
      credential = parsed.credential;
      break;
    case "unknown":
      return c.json(
        { error: { code: "BAD_REQUEST", message: "Unrecognized credential format" } },
        400,
      );
  }

  // Verify using composite DID resolver (supports did:key, did:jwk, did:web)
  const { DIDKeyResolver, DIDJwkResolver, DIDWebResolver, CompositeDIDResolver } =
    await import("@opencred/did");
  const { verifyCredential } = await import("@opencred/verification");
  const { getTrustStore } = await import("../trust-store.js");
  const { getDeDiClient } = await import("../dedi-singleton.js");

  const compositeResolver = new CompositeDIDResolver(
    new Map([
      ["key", new DIDKeyResolver()],
      ["jwk", new DIDJwkResolver()],
      ["web", new DIDWebResolver()],
    ]),
  );

  // Use the CSCA trust store loaded at server startup. The trust store is
  // loaded once from OPENCRED_CSCA_TRUST_STORE_PATH during bootstrap and
  // shared across all verification requests. Required for DSC-backed
  // credentials per nfh-trust-labs/opencred#316.
  const trustStore = getTrustStore();
  const trustAnchors = trustStore ? trustStore.toPemArray() : undefined;

  const dediClient = getDeDiClient();
  const verificationResult = await verifyCredential(credential, {
    didResolver: compositeResolver,
    trustAnchors,
    dediClient: dediClient ?? undefined,
  });

  // SECURITY: Do not leak `detail` strings or the name of the first failed
  // check in the response message — those can include operator config (e.g.
  // CSCA subject DN) or parser errors. Callers get the stable top-level
  // `code` enum for programmatic handling instead. See
  // `sanitizeChecksForServerResponse` / `buildVerifyResponseBody` above for
  // the rationale.
  credentialsVerifiedTotal.inc({ result: verificationResult.verified ? "valid" : "invalid" });

  return c.json(buildVerifyResponseBody(verificationResult));
});

export { credentials };
