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
import type { SchemaRegistry } from "@opencred/schema-engine";
import { getSchemaRegistry } from "../schema-registry-singleton.js";
import { getValidator } from "../validator-singleton.js";
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
import { getLogger } from "../logger.js";

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
    logoDataUri: z.string().startsWith("data:image/", "Must be data URI").optional(),
    logoWidth: z.number().int().min(10).max(200).optional(),
    logoHeight: z.number().int().min(10).max(200).optional(),
    footerText: z.string().max(500).optional(),
    sealDataUri: z.string().startsWith("data:image/", "Must be data URI").optional(),
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
 * Upper bound on how many bytes of a long string value we scan for PEM
 * headers. PEM blocks always begin with the `-----BEGIN ...-----` marker at
 * the top of the blob, so a 4 KiB prefix is far more than enough to catch
 * any realistic "key pasted into a CSV cell" attack without scanning the
 * entire `csvContent` field (which can be up to 200 MiB under
 * `OPENCRED_MAX_BATCH_BODY_BYTES`). See Anand's P3-03.
 */
const PEM_SCAN_PREFIX_BYTES = 4_096;

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
    if (typeof value === "string") {
      // Long string? Only scan the head. A PEM header always appears near
      // the top of a key blob; scanning the tail adds no coverage but can
      // block the event loop for tens of ms on a 200 MiB CSV payload.
      const sample =
        value.length > PEM_SCAN_PREFIX_BYTES ? value.slice(0, PEM_SCAN_PREFIX_BYTES) : value;
      if (PEM_PRIVATE_KEY_RE.test(sample)) {
        throw new ValidationError(
          `Request rejected: field at "${path || "<root>"}" looks like a PEM-encoded private key. ` +
            "OpenCred never accepts private key material via the HTTP API.",
        );
      }
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

// The Validator is a single process-wide instance held by
// `validator-singleton.ts`. The route uses `getValidator()` instead of a
// lazily-cached module-scope Validator to avoid binding the route's
// validator to a different registry snapshot than the one the batch engine
// or CSV parser see — see Anand's P1-01.
function getRegistry(): SchemaRegistry {
  return getSchemaRegistry();
}

// --- Request schemas ---

const issueRequestSchema = z
  .object({
    /**
     * Built-in registry id (e.g. `functional-identity/v1`). Optional only
     * when `inlineSchema` is supplied — at least one of the two must be
     * present (enforced by the `.refine()` below).
     */
    schemaId: z.string().optional(),
    /**
     * Pasted JSON Schema document. When present, the server validates the
     * `credentialSubject` against this schema instead of the registry, and
     * the credential's `credentialSchema.id` priority shifts so the inline
     * schema's `$id` (or a data-URI of the schema body) is referenced.
     *
     * The same defense-in-depth `rejectKeyMaterial()` walk runs over the
     * full request body before this schema is even read, so an inline
     * schema that smuggles a PEM block in any nested string is rejected
     * with 400 just like every other field.
     */
    inlineSchema: z.record(z.unknown()).optional(),
    /**
     * Optional JSON-LD context document to attach when proofFormat is
     * `data-integrity`. RDFC-1.0 canonicalization in safe mode requires
     * every term in the credential to be defined in some context, and an
     * inline-schema credential has no built-in context to fall back on.
     * Mirrors the desktop's `inlineContext` flow.
     */
    inlineContext: z.record(z.unknown()).optional(),
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
    packageFormats: z.array(z.enum(["qr-png", "qr-svg", "pdf", "json", "json-compact"])).optional(),
    customization: customizationSchema,
  })
  .refine((data) => Boolean(data.schemaId) || Boolean(data.inlineSchema), {
    message:
      "Either schemaId (built-in registry) or inlineSchema (custom JSON Schema document) must be provided",
    path: ["schemaId"],
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

  // Validate credential subject against schema. Two paths:
  //   1. inlineSchema present → compile + validate ad-hoc (no registry lookup)
  //   2. inlineSchema absent  → registry lookup by schemaId (existing behaviour)
  if (parsed.inlineSchema) {
    getValidator().validateInlineOrThrow(
      parsed.inlineSchema,
      parsed.credentialSubject,
      parsed.schemaId,
    );
  } else if (parsed.schemaId) {
    getValidator().validateOrThrow(parsed.schemaId, parsed.credentialSubject);
  }
  // The Zod `.refine()` on issueRequestSchema guarantees at least one of
  // schemaId / inlineSchema is set, so an `else` branch is unreachable.

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
  //
  // Priority for inline-schema credentials:
  //   1. parsed.inlineContext  — caller pasted a context alongside the schema
  //   2. registry context for schemaId (when schemaId is in the registry)
  // Without a context, RDFC-1.0 safe mode will reject undefined terms.
  if (parsed.proofFormat === "data-integrity") {
    if (parsed.inlineContext) {
      builder.addContext(parsed.inlineContext);
    } else if (parsed.schemaId) {
      const builtInContextUrl = getRegistry().getContextForType(parsed.schemaId);
      if (builtInContextUrl) {
        builder.addContext(builtInContextUrl);
      }
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
  //   2. inlineSchema.$id, if the caller pasted a schema with one
  //   3. registry schema's own $id (for built-in schemaIds)
  //   4. a data-URI containing the base64-encoded schema as a last resort,
  //      preferring the inline schema body if present, so the credential is
  //      never silently shipped without a schema reference.
  const credentialSchemaId = ((): string => {
    if (parsed.credentialSchemaUrl) {
      return parsed.credentialSchemaUrl;
    }
    // Inline schema is the highest-priority source of a $id when the
    // caller pasted a schema. We still check the registry below so that a
    // request with both schemaId AND inlineSchema doesn't lose the
    // built-in $id when the inline schema lacks one.
    if (parsed.inlineSchema) {
      const inlineId = (parsed.inlineSchema as { $id?: unknown })["$id"];
      if (typeof inlineId === "string" && inlineId.length > 0) {
        return inlineId;
      }
    }
    let schemaObject: Record<string, unknown> = parsed.inlineSchema ?? {};
    if (parsed.schemaId) {
      try {
        const def = getRegistry().getSchema(parsed.schemaId);
        // Only fall back to the registry schema when no inline schema was
        // supplied — otherwise the caller's pasted schema wins.
        if (!parsed.inlineSchema) {
          schemaObject = def.schema as Record<string, unknown>;
        }
        const id = (def.schema as { $id?: unknown })["$id"];
        if (typeof id === "string" && id.length > 0 && !parsed.inlineSchema) {
          return id;
        }
      } catch {
        // Schema not in the registry. Fall through to the data-URI fallback
        // with whatever object we have — an empty object is still a
        // well-formed JSON Schema document.
      }
    }
    const base64 = Buffer.from(JSON.stringify(schemaObject), "utf8").toString("base64");
    return `data:application/schema+json;base64,${base64}`;
  })();
  builder.setSchema({ id: credentialSchemaId, type: "JsonSchema" });

  const unsigned = builder.build();

  // Sign based on proof format
  const proofFormat = parsed.proofFormat;
  // SD-JWT VC needs a `vct` (verifiable credential type) header. Priority:
  //   additionalTypes[0] — explicit, wins
  //   schemaId           — when issuing against a registry id
  //   inlineSchema.title — for pasted schemas with a human-readable title
  // SD-JWT-VC verifiers route on `vct`, so a generic fallback would produce
  // non-discriminating tokens; reject early below if none of the three is set.
  const inlineSchemaTitle =
    parsed.inlineSchema && typeof (parsed.inlineSchema as { title?: unknown })["title"] === "string"
      ? ((parsed.inlineSchema as { title?: string })["title"] as string)
      : undefined;
  const vct = parsed.additionalTypes?.[0] ?? parsed.schemaId ?? inlineSchemaTitle;
  if (proofFormat === "sd-jwt-vc" && !vct) {
    throw new ValidationError(
      "sd-jwt-vc requires a credential type identifier. Provide one of: " +
        "additionalTypes[0], schemaId, or inlineSchema.title.",
    );
  }

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
      // The validation above guarantees vct is set whenever proofFormat is sd-jwt-vc.
      const sdJwtOptions = {
        selectiveDisclosureClaims: parsed.selectiveDisclosureClaims ?? [],
        vct: vct as string,
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
  if (parsed.packageFormats && parsed.packageFormats.length > 0) {
    // For data-integrity output, `signedOutput` is the JSON-stringified
    // VerifiableCredential — parse it back into an object so the
    // packager has the full VC tree. For compact tokens
    // (vc-jwt / sd-jwt-vc) the packager accepts the raw token string
    // directly: it decodes the payload for the PDF layout and embeds
    // the original token verbatim into the QR.
    const credentialForPackaging: Parameters<typeof packageCredential>[0] = isCompactToken
      ? signedOutput
      : (JSON.parse(signedOutput) as Parameters<typeof packageCredential>[0]);
    const customization = parsed.customization as TemplateCustomization | undefined;
    const result = await packageCredential(
      credentialForPackaging,
      parsed.packageFormats as PackageFormat[],
      { customization },
    );
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
  //
  // OBSERVABILITY (Anand's P2-04): the stripped `detail` strings are safe
  // to log server-side (they stay off the wire, never reach an external
  // caller) and are the only diagnostic operators have for intermittent
  // verification failures — did:web resolution timeouts, X.509 chain
  // issues, etc. Emit at DEBUG so production log volume stays bounded and
  // the operator opts in via `OPENCRED_LOG_LEVEL=debug`.
  getLogger().debug(
    { code: verificationResult.code, checks: verificationResult.checks },
    "Credential verification result (detail stripped from HTTP response)",
  );

  credentialsVerifiedTotal.inc({ result: verificationResult.verified ? "valid" : "invalid" });

  return c.json(buildVerifyResponseBody(verificationResult));
});

export { credentials };
