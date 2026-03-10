import { Hono } from "hono";
import { z } from "zod";
import { createCapabilityToken } from "@opencred/auth";
import { ValidationError, VerificationError, PayloadTooLargeError } from "@opencred/shared";
import { verifyCredential, detectFormat, parseSdJwtVc, processDisclosures } from "@opencred/verification";
import type { VerifierConfig } from "@opencred/verification";
import type { VerifiableCredential } from "@opencred/vc-core";

// --- Constants ---

/** Maximum allowed JWT/SD-JWT payload size in bytes (10 KB). */
const MAX_JWT_BYTES = 10 * 1024;

// --- Zod schemas for request validation ---

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

export interface BusinessVcOnboardingDeps {
  jwtSigningKey: Uint8Array;
  jwtIssuer: string;
  jwtExpirySeconds: number;
  verifierConfig?: VerifierConfig;
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

export function createBusinessVcOnboardingRoutes(deps: BusinessVcOnboardingDeps) {
  const { jwtSigningKey, jwtIssuer, jwtExpirySeconds, verifierConfig } = deps;
  const businessVc = new Hono();

  businessVc.post("/business-vc", async (c) => {
    let rawBody: unknown;
    try {
      rawBody = await c.req.json();
    } catch {
      throw new ValidationError("Invalid JSON in request body");
    }
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

    return c.json({ namespace, capabilityToken, issuerIdentifier: subject, expiresAt }, 201);
  });

  // POST /type-d — alias for /business-vc (PRD endpoint path alignment #173)
  businessVc.post("/type-d", async (c) => {
    const url = new URL(c.req.url);
    url.pathname = url.pathname.replace(/\/type-d$/, "/business-vc");
    const cloned = new Request(url.toString(), c.req.raw);
    return businessVc.fetch(cloned, c.env);
  });

  // 405 for non-POST methods
  businessVc.all("/business-vc", (c) =>
    c.json({ error: { code: "METHOD_NOT_ALLOWED", message: "Use POST" } }, 405),
  );
  businessVc.all("/type-d", (c) =>
    c.json({ error: { code: "METHOD_NOT_ALLOWED", message: "Use POST" } }, 405),
  );

  return businessVc;
}
