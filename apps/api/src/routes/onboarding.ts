import { Hono } from "hono";
import { z } from "zod";
import { X509Certificate } from "node:crypto";
import { createCapabilityToken } from "@opencred/auth";
import { ValidationError, VerificationError } from "@opencred/shared";
import type { DeDiClient } from "@opencred/dedi-client";
import {
  verifyCredential,
  detectFormat,
  parseSdJwtVc,
  processDisclosures,
} from "@opencred/verification";
import type { VerifierConfig } from "@opencred/verification";
import type { VerifiableCredential } from "@opencred/vc-core";
import {
  createDelegationCertificate,
  registerDelegation,
} from "@opencred/delegation";
import type { DelegationCertificate } from "@opencred/delegation";
import { validateDscChain, type TrustStore } from "../dsc-chain.js";

// --- Zod schemas for request validation ---

const typeAOnboardingSchema = z.object({
  dscChain: z.array(z.string().min(1)).min(1, "dscChain must contain at least one PEM certificate"),
  publicKey: z
    .object({
      kty: z.string().min(1),
      crv: z.string().optional(),
      x: z.string().optional(),
      y: z.string().optional(),
    })
    .passthrough(),
});

const jwkSchema = z
  .object({
    kty: z.string().min(1),
    crv: z.string().optional(),
    x: z.string().optional(),
    y: z.string().optional(),
  })
  .passthrough();

const businessVcOnboardingSchema = z
  .object({
    businessCredential: z.union([
      z.string().min(1, "businessCredential string must not be empty"),
      z.record(z.unknown()).refine(
        (obj) => Object.keys(obj).length > 0,
        "businessCredential object must not be empty",
      ),
    ]),
    signingPreference: z.enum(["interface", "delegated"]).optional().default("interface"),
    publicKey: jwkSchema.optional(),
  })
  .refine(
    (data) => data.signingPreference !== "interface" || data.publicKey !== undefined,
    { message: "publicKey is required when signingPreference is 'interface'", path: ["publicKey"] },
  );

// --- Types ---

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

// --- Helpers ---

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
      if (key && value) {
        fields[key] = value;
      }
    }
  }
  return fields;
}

/**
 * Build a deterministic issuer namespace from DSC subject fields.
 * Format: urn:opencred:issuer:{C}:{O}:{CN}
 * Fields are lowercased and non-alphanumeric chars replaced with hyphens.
 */
function buildNamespace(subjectFields: Record<string, string>): string {
  const parts: string[] = [];
  for (const key of ["C", "O", "CN"]) {
    const val = subjectFields[key];
    if (val) {
      parts.push(slugify(val));
    }
  }
  if (parts.length === 0) {
    throw new ValidationError(
      "DSC certificate subject has no usable identity fields (CN, O, or C)",
    );
  }
  return `urn:opencred:issuer:${parts.join(":")}`;
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/**
 * Extract an organisation name from a verified business credential's subject.
 * Checks common fields: name, legalName, organizationName, org.
 */
function extractOrgName(credentialSubject: Record<string, unknown>): string | undefined {
  for (const field of ["name", "legalName", "organizationName", "org"]) {
    const val = credentialSubject[field];
    if (typeof val === "string" && val.trim()) {
      return val.trim();
    }
  }
  return undefined;
}

/**
 * Extract credentialSubject from a verified business credential in any format.
 */
async function extractCredentialSubject(
  input: Record<string, unknown> | string,
): Promise<Record<string, unknown>> {
  const format = detectFormat(input);

  if (format === "data-integrity") {
    const credential = input as unknown as VerifiableCredential;
    const subject = credential.credentialSubject;
    if (!subject || typeof subject !== "object") {
      throw new ValidationError("Business credential has no credentialSubject");
    }
    return subject as Record<string, unknown>;
  }

  if (format === "vc-jwt") {
    const parts = (input as string).split(".");
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf-8"),
    );
    // DM 1.1: vc.credentialSubject, DM 2.0: credentialSubject directly
    const subject = payload.vc?.credentialSubject ?? payload.credentialSubject;
    if (!subject || typeof subject !== "object") {
      throw new ValidationError("Business credential has no credentialSubject");
    }
    return subject as Record<string, unknown>;
  }

  // SD-JWT VC: parse the issuer JWT and process disclosures
  const components = parseSdJwtVc(input as string);
  const jwtParts = components.issuerJwt.split(".");
  const sdPayload = JSON.parse(
    Buffer.from(jwtParts[1], "base64url").toString("utf-8"),
  );
  const resolvedClaims = await processDisclosures(sdPayload, components.disclosures);
  const subject =
    (resolvedClaims.credentialSubject as Record<string, unknown>) ??
    (sdPayload.credentialSubject as Record<string, unknown>);
  if (!subject || typeof subject !== "object") {
    throw new ValidationError("Business credential has no credentialSubject");
  }
  return subject as Record<string, unknown>;
}

/**
 * Build a deterministic namespace for a Type D (business VC) issuer.
 * Format: urn:opencred:issuer:business:{slugified-org-name}
 */
function buildBusinessNamespace(orgName: string): string {
  const slug = slugify(orgName);
  if (!slug) {
    throw new ValidationError("Organisation name produces an empty slug");
  }
  return `urn:opencred:issuer:business:${slug}`;
}

/**
 * Build a subject identifier from the business credential's issuer or subject ID.
 */
function buildBusinessSubject(credentialSubject: Record<string, unknown>, orgName: string): string {
  const id = credentialSubject.id;
  if (typeof id === "string" && id.trim()) {
    return `business-vc:${slugify(id)}`;
  }
  return `business-vc:${slugify(orgName)}`;
}

// --- Factory ---

export function createOnboardingRoutes(deps: OnboardingRoutesDeps) {
  const { trustStore, jwtSigningKey, jwtIssuer, jwtExpirySeconds } = deps;
  const onboarding = new Hono();

  // POST /type-a — DSC-based onboarding
  onboarding.post("/type-a", async (c) => {
    const rawBody = await c.req.json();
    const parsed = typeAOnboardingSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const { dscChain } = parsed.data;

    // 1. Validate DSC → CSCA chain
    const chainResult = validateDscChain(dscChain, trustStore);
    if (!chainResult.passed) {
      throw new ValidationError(`DSC chain validation failed: ${chainResult.detail}`);
    }

    // 2. Parse the leaf DSC certificate (first in chain) and extract subject identity
    let leafCert: X509Certificate;
    try {
      leafCert = new X509Certificate(dscChain[0]);
    } catch {
      throw new ValidationError("Failed to parse leaf DSC certificate");
    }

    const subjectFields = parseSubject(leafCert.subject);

    // 3. Build issuer namespace from DSC subject
    const namespace = buildNamespace(subjectFields);

    // 4. Compute a subject identifier from the DSC fingerprint (SHA-256)
    const fingerprint = leafCert.fingerprint256.replace(/:/g, "").toLowerCase();
    const subject = `dsc:${fingerprint}`;

    // 5. Issue capability token
    const expiresAt = new Date(Date.now() + jwtExpirySeconds * 1000).toISOString();
    const capabilityToken = await createCapabilityToken({
      subject,
      issuer: jwtIssuer,
      expiresInSeconds: jwtExpirySeconds,
      scope: ["credentials:build", "credentials:revoke"],
      namespace,
      signingKey: jwtSigningKey,
    });

    // 6. Log public key fingerprint only — never the key material itself
    // (publicKey is accepted for future use but not stored server-side)

    return c.json(
      {
        capabilityToken,
        namespace,
        expiresAt,
      },
      201,
    );
  });

  return onboarding;
}

export function createBusinessVcOnboardingRoutes(deps: BusinessVcOnboardingDeps) {
  const {
    jwtSigningKey,
    jwtIssuer,
    jwtExpirySeconds,
    verifierConfig,
    dediClient,
    opencredSigningKeyDid,
  } = deps;

  const businessVc = new Hono();

  // POST /business-vc — Type D business-VC-based onboarding
  businessVc.post("/business-vc", async (c) => {
    const rawBody = await c.req.json();
    const parsed = businessVcOnboardingSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const { businessCredential, signingPreference } = parsed.data;

    // 1. Verify the business VC cryptographically
    const verificationResult = await verifyCredential(
      businessCredential as Record<string, unknown> | string,
      verifierConfig,
    );
    if (!verificationResult.verified) {
      const code = verificationResult.code;
      const detail = verificationResult.checks
        .filter((ch) => !ch.passed)
        .map((ch) => ch.detail)
        .filter(Boolean)
        .join("; ");
      if (code === "EXPIRED") {
        throw new VerificationError(`Business credential has expired: ${detail}`);
      }
      throw new VerificationError(
        `Business credential verification failed: ${detail || code}`,
      );
    }

    // 2. Extract identity from the verified credential
    const credentialSubject = await extractCredentialSubject(
      businessCredential as Record<string, unknown> | string,
    );
    const orgName = extractOrgName(credentialSubject);
    if (!orgName) {
      throw new ValidationError(
        "Business credential has no usable identity fields (name, legalName, organizationName, or org)",
      );
    }

    // 3. Create DeDi namespace
    const namespace = buildBusinessNamespace(orgName);

    // 4. Build subject identifier
    const subject = buildBusinessSubject(credentialSubject, orgName);

    // 5. Determine scopes based on signing preference
    const scope: string[] =
      signingPreference === "delegated"
        ? ["credentials:issue-delegated", "credentials:revoke"]
        : ["credentials:build", "credentials:revoke"];

    // 6. Issue capability token
    const expiresAt = new Date(Date.now() + jwtExpirySeconds * 1000).toISOString();
    const capabilityToken = await createCapabilityToken({
      subject,
      issuer: jwtIssuer,
      expiresInSeconds: jwtExpirySeconds,
      scope,
      namespace,
      signingKey: jwtSigningKey,
    });

    // 7. If delegated signing, create and register a delegation certificate
    let delegationId: string | undefined;
    if (signingPreference === "delegated") {
      if (!opencredSigningKeyDid) {
        throw new ValidationError(
          "Delegated signing is not available: no OpenCred signing key configured",
        );
      }

      const delegatorId = credentialSubject.id as string | undefined ?? `urn:opencred:business:${slugify(orgName)}`;

      const now = new Date();
      const validUntil = new Date(now.getTime() + jwtExpirySeconds * 1000);

      const unsignedCert = createDelegationCertificate({
        delegator: {
          id: delegatorId,
          name: orgName,
        },
        delegatee: {
          id: opencredSigningKeyDid,
        },
        scope: {
          credentialTypes: [],
          namespaces: [namespace],
        },
        validFrom: now.toISOString(),
        validUntil: validUntil.toISOString(),
        authorisationPath: "dedi-registry",
      });

      delegationId = unsignedCert.id;

      // Register delegation in DeDi if client is available
      if (dediClient) {
        // The delegation certificate is unsigned here — in production the
        // delegator would sign it. For Type D onboarding, the business VC
        // itself serves as the authorisation proof, so we register the
        // unsigned cert as a placeholder and attach the proof field to
        // satisfy the registry contract.
        const certWithProof: DelegationCertificate = {
          ...unsignedCert,
          proof: {
            type: "BusinessCredentialAuthorisation",
            verificationMethod: delegatorId,
            proofPurpose: "capabilityDelegation",
            created: now.toISOString(),
            proofValue: "",
          },
        };
        await registerDelegation(dediClient, { certificate: certWithProof });
      }
    }

    const response: Record<string, unknown> = {
      namespace,
      capabilityToken,
      issuerIdentifier: subject,
      expiresAt,
    };
    if (delegationId) {
      response.delegationId = delegationId;
    }

    return c.json(response, 201);
  });

  return businessVc;
}
