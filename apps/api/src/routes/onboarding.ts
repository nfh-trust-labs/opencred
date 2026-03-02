import { Hono } from "hono";
import { z } from "zod";
import { X509Certificate, createHash } from "node:crypto";
import { createCapabilityToken } from "@opencred/auth";
import { ValidationError, VerificationError, PayloadTooLargeError } from "@opencred/shared";
import type { DeDiClient } from "@opencred/dedi-client";
import { verifyCredential, detectFormat, parseSdJwtVc, processDisclosures } from "@opencred/verification";
import type { VerifierConfig } from "@opencred/verification";
import type { VerifiableCredential } from "@opencred/vc-core";
import { createDelegationCertificate, registerDelegation } from "@opencred/delegation";
import type { DelegationCertificate } from "@opencred/delegation";
import { validateDscChain, type TrustStore } from "../dsc-chain.js";

// --- Constants ---

/** Maximum allowed JWT/SD-JWT payload size in bytes (10 KB). */
const MAX_JWT_BYTES = 10 * 1024;

// --- Zod schemas for request validation ---

const typeAOnboardingSchema = z.object({
  dscChain: z.array(z.string().min(1)).min(1, "dscChain must contain at least one PEM certificate"),
  publicKey: z.object({ kty: z.string().min(1), crv: z.string().optional(), x: z.string().optional(), y: z.string().optional() }).passthrough(),
});

const jwkSchema = z.object({ kty: z.string().min(1), crv: z.string().optional(), x: z.string().optional(), y: z.string().optional() }).passthrough();

const businessVcOnboardingSchema = z.object({
  businessCredential: z.union([
    z.string().min(1, "businessCredential string must not be empty"),
    z.record(z.unknown()).refine((obj) => Object.keys(obj).length > 0, "businessCredential object must not be empty"),
  ]),
  signingPreference: z.enum(["interface", "delegated"]).optional().default("interface"),
  publicKey: jwkSchema.optional(),
}).refine((data) => data.signingPreference !== "interface" || data.publicKey !== undefined, {
  message: "publicKey is required when signingPreference is 'interface'",
  path: ["publicKey"],
});

export interface OnboardingRoutesDeps {
  trustStore: TrustStore;
  jwtSigningKey: Uint8Array;
  jwtIssuer: string;
  jwtExpirySeconds: number;
}

export interface BusinessVcOnboardingDeps {
  jwtSigningKey: Uint8Array;
  jwtIssuer: string;
  jwtExpirySeconds: number;
  verifierConfig?: VerifierConfig;
  dediClient?: DeDiClient;
  opencredSigningKeyDid?: string;
}

/**
 * Validate that a JWT/SD-JWT string does not exceed the maximum allowed size.
 * Rejects payloads larger than MAX_JWT_BYTES (10 KB) to prevent resource
 * exhaustion during Base64 decoding and JSON parsing (#139).
 */
function validateJwtSize(jwt: string): void {
  const byteLength = Buffer.byteLength(jwt, "utf-8");
  if (byteLength > MAX_JWT_BYTES) {
    throw new PayloadTooLargeError(
      `JWT payload exceeds maximum allowed size (${byteLength} bytes > ${MAX_JWT_BYTES} bytes)`,
    );
  }
}

/**
 * Parse X.509 subject string into a key-value map.
 * Node.js X509Certificate.subject returns newline-delimited "KEY=VALUE" pairs.
 */
function parseSubject(subject: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const line of subject.split("\n")) {
    const eqIdx = line.indexOf("=");
    if (eqIdx > 0) {
      const key = line.slice(0, eqIdx).trim();
      const value = line.slice(eqIdx + 1).trim();
      if (key && value) fields[key] = value;
    }
  }
  return fields;
}

function buildNamespace(subjectFields: Record<string, string>): string {
  const parts: string[] = [];
  for (const key of ["C", "O", "CN"]) {
    const val = subjectFields[key];
    if (val) parts.push(slugify(val));
  }
  if (parts.length === 0) throw new ValidationError("DSC certificate subject has no usable identity fields (CN, O, or C)");
  return `urn:opencred:issuer:${parts.join(":")}`;
}

function slugify(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function extractOrgName(credentialSubject: Record<string, unknown>): string | undefined {
  for (const field of ["name", "legalName", "organizationName", "org"]) {
    const val = credentialSubject[field];
    if (typeof val === "string" && val.trim()) return val.trim();
  }
  return undefined;
}

async function extractCredentialSubject(input: Record<string, unknown> | string): Promise<Record<string, unknown>> {
  const format = detectFormat(input);

  if (format === "data-integrity") {
    const credential = input as unknown as VerifiableCredential;
    const subject = credential.credentialSubject;
    if (!subject || typeof subject !== "object") throw new ValidationError("Business credential has no credentialSubject");
    return subject as Record<string, unknown>;
  }

  if (format === "vc-jwt") {
    // Bounds check before parsing (#139)
    validateJwtSize(input as string);
    const parts = (input as string).split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
    const subject = payload.vc?.credentialSubject ?? payload.credentialSubject;
    if (!subject || typeof subject !== "object") throw new ValidationError("Business credential has no credentialSubject");
    return subject as Record<string, unknown>;
  }

  // SD-JWT VC: parse the issuer JWT and process disclosures
  // Bounds check before parsing (#139)
  validateJwtSize(input as string);
  const components = parseSdJwtVc(input as string);
  const jwtParts = components.issuerJwt.split(".");
  const sdPayload = JSON.parse(Buffer.from(jwtParts[1], "base64url").toString("utf-8"));
  const resolvedClaims = await processDisclosures(sdPayload, components.disclosures);
  const subject = (resolvedClaims.credentialSubject as Record<string, unknown>) ?? (sdPayload.credentialSubject as Record<string, unknown>);
  if (!subject || typeof subject !== "object") throw new ValidationError("Business credential has no credentialSubject");
  return subject as Record<string, unknown>;
}

function buildBusinessNamespace(orgName: string): string {
  const slug = slugify(orgName);
  if (!slug) throw new ValidationError("Organisation name produces an empty slug");
  return `urn:opencred:issuer:business:${slug}`;
}

function buildBusinessSubject(credentialSubject: Record<string, unknown>, orgName: string): string {
  const id = credentialSubject.id;
  if (typeof id === "string" && id.trim()) return `business-vc:${slugify(id)}`;
  return `business-vc:${slugify(orgName)}`;
}

export function createOnboardingRoutes(deps: OnboardingRoutesDeps) {
  const { trustStore, jwtSigningKey, jwtIssuer, jwtExpirySeconds } = deps;
  const onboarding = new Hono();

  onboarding.post("/type-a", async (c) => {
    const rawBody = await c.req.json();
    const parsed = typeAOnboardingSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }
    const { dscChain } = parsed.data;
    const chainResult = validateDscChain(dscChain, trustStore);
    if (!chainResult.passed) throw new ValidationError(`DSC chain validation failed: ${chainResult.detail}`);

    let leafCert: X509Certificate;
    try { leafCert = new X509Certificate(dscChain[0]); } catch { throw new ValidationError("Failed to parse leaf DSC certificate"); }

    const subjectFields = parseSubject(leafCert.subject);
    const namespace = buildNamespace(subjectFields);
    const fingerprint = leafCert.fingerprint256.replace(/:/g, "").toLowerCase();
    const subject = `dsc:${fingerprint}`;

    const expiresAt = new Date(Date.now() + jwtExpirySeconds * 1000).toISOString();
    const capabilityToken = await createCapabilityToken({ subject, issuer: jwtIssuer, expiresInSeconds: jwtExpirySeconds, scope: ["credentials:build", "credentials:revoke"], namespace, signingKey: jwtSigningKey });

    return c.json({ capabilityToken, namespace, expiresAt }, 201);
  });

  return onboarding;
}

export function createBusinessVcOnboardingRoutes(deps: BusinessVcOnboardingDeps) {
  const { jwtSigningKey, jwtIssuer, jwtExpirySeconds, verifierConfig, dediClient, opencredSigningKeyDid } = deps;
  const businessVc = new Hono();

  businessVc.post("/business-vc", async (c) => {
    const rawBody = await c.req.json();
    const parsed = businessVcOnboardingSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const { businessCredential, signingPreference } = parsed.data;

    const verificationResult = await verifyCredential(businessCredential as Record<string, unknown> | string, verifierConfig);
    if (!verificationResult.verified) {
      const code = verificationResult.code;
      const detail = verificationResult.checks.filter((ch) => !ch.passed).map((ch) => ch.detail).filter(Boolean).join("; ");
      if (code === "EXPIRED") throw new VerificationError(`Business credential has expired: ${detail}`);
      throw new VerificationError(`Business credential verification failed: ${detail || code}`);
    }

    const credentialSubject = await extractCredentialSubject(businessCredential as Record<string, unknown> | string);
    const orgName = extractOrgName(credentialSubject);
    if (!orgName) throw new ValidationError("Business credential has no usable identity fields (name, legalName, organizationName, or org)");

    const namespace = buildBusinessNamespace(orgName);
    const subject = buildBusinessSubject(credentialSubject, orgName);
    const scope: string[] = signingPreference === "delegated" ? ["credentials:issue-delegated", "credentials:revoke"] : ["credentials:build", "credentials:revoke"];

    const expiresAt = new Date(Date.now() + jwtExpirySeconds * 1000).toISOString();
    const capabilityToken = await createCapabilityToken({ subject, issuer: jwtIssuer, expiresInSeconds: jwtExpirySeconds, scope, namespace, signingKey: jwtSigningKey });

    let delegationId: string | undefined;
    if (signingPreference === "delegated") {
      if (!opencredSigningKeyDid) throw new ValidationError("Delegated signing is not available: no OpenCred signing key configured");
      const delegatorId = (credentialSubject.id as string | undefined) ?? `urn:opencred:business:${slugify(orgName)}`;
      const now = new Date();
      const validUntil = new Date(now.getTime() + jwtExpirySeconds * 1000);
      const unsignedCert = createDelegationCertificate({ delegator: { id: delegatorId, name: orgName }, delegatee: { id: opencredSigningKeyDid }, scope: { credentialTypes: [], namespaces: [namespace] }, validFrom: now.toISOString(), validUntil: validUntil.toISOString(), authorisationPath: "dedi-registry" });
      delegationId = unsignedCert.id;
      if (dediClient) {
        // The delegation certificate is unsigned here — in production the
        // delegator would sign it. For Type D onboarding, the business VC
        // itself serves as the authorisation proof, so we register the
        // unsigned cert as a placeholder and attach the proof field to
        // satisfy the registry contract.
        const businessCredentialDigest = createHash("sha256")
          .update(
            typeof businessCredential === "string"
              ? businessCredential
              : JSON.stringify(businessCredential),
          )
          .digest("base64url");

        const certWithProof: DelegationCertificate = {
          ...unsignedCert,
          proof: {
            type: "BusinessCredentialAuthorisation",
            verificationMethod: delegatorId,
            proofPurpose: "capabilityDelegation",
            created: now.toISOString(),
            proofValue: `z${businessCredentialDigest}`,
          },
        };
        await registerDelegation(dediClient, { certificate: certWithProof });
      }
    }

    const response: Record<string, unknown> = { namespace, capabilityToken, issuerIdentifier: subject, expiresAt };
    if (delegationId) response.delegationId = delegationId;
    return c.json(response, 201);
  });

  // POST /type-d — alias for /business-vc (PRD endpoint path alignment #173)
  businessVc.post("/type-d", async (c) => {
    const url = new URL(c.req.url);
    url.pathname = url.pathname.replace(/\/type-d$/, "/business-vc");
    const cloned = new Request(url.toString(), c.req.raw);
    return businessVc.fetch(cloned, c.env);
  });

  return businessVc;
}
