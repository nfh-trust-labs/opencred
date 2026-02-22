import { Hono } from "hono";
import { z } from "zod";
import { X509Certificate } from "node:crypto";
import { createCapabilityToken } from "@opencred/auth";
import { ValidationError } from "@opencred/shared";
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

// --- Types ---

export interface OnboardingRoutesDeps {
  trustStore: TrustStore;
  jwtSigningKey: Uint8Array;
  jwtIssuer: string;
  jwtExpirySeconds: number;
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
