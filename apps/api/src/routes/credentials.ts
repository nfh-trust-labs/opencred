import { Hono } from "hono";
import { z } from "zod";
import { zValidator } from "@hono/zod-validator";
import { randomUUID } from "node:crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import type { UnsignedCredential } from "@opencred/vc-core";
import { prepareProof, completeProof } from "@opencred/crypto";
import type { ProofConfig } from "@opencred/crypto";
import { createRegistry, Validator } from "@opencred/schema-engine";
import { TTLStore } from "@opencred/state";
import { ValidationError, SessionExpiredError } from "@opencred/shared";
import type { EnvConfig } from "@opencred/shared";
import { authMiddleware, type AuthMiddlewareOptions } from "../middleware/auth.js";

// ---------------------------------------------------------------------------
// Request schemas
// ---------------------------------------------------------------------------

const buildRequestSchema = z.object({
  schema: z.string().min(1, "schema is required"),
  issuer: z.string().min(1, "issuer DID is required"),
  publicKey: z.string().min(1, "publicKey is required"),
  credentialSubject: z.record(z.unknown()).refine((v) => Object.keys(v).length > 0, {
    message: "credentialSubject must not be empty",
  }),
  validFrom: z.string().min(1, "validFrom is required"),
  validUntil: z.string().optional(),
  revocationRegistryUrl: z.string().min(1, "revocationRegistryUrl is required"),
});

const packageRequestSchema = z.object({
  sessionId: z.string().uuid("sessionId must be a valid UUID"),
  signature: z.string().min(1, "signature is required"),
});

// ---------------------------------------------------------------------------
// Session store types
// ---------------------------------------------------------------------------

interface SigningSession {
  unsignedCredential: UnsignedCredential;
  proofConfig: ProofConfig;
  publicKey: string;
  dataToSign: Uint8Array;
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export interface CredentialsRouteDeps {
  config: EnvConfig;
  authOptions: AuthMiddlewareOptions;
}

export function createCredentialsRoute(deps: CredentialsRouteDeps) {
  const { config, authOptions } = deps;
  const credentials = new Hono();

  const registry = createRegistry();
  const validator = new Validator(registry);

  const sessionStore = new TTLStore<SigningSession>(
    config.SESSION_TTL_MS,
    config.SESSION_SWEEP_INTERVAL_MS,
  );

  // -----------------------------------------------------------------------
  // POST /credentials/build — Interface Signing phase 1
  // -----------------------------------------------------------------------
  credentials.post(
    "/build",
    authMiddleware(authOptions, "credentials:write"),
    zValidator("json", buildRequestSchema, (result, c) => {
      if (!result.success) {
        const fieldErrors = result.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        }));
        return c.json(
          {
            error: {
              code: "VALIDATION_ERROR",
              message: "Request validation failed",
              validationErrors: fieldErrors,
            },
          },
          400,
        );
      }
    }),
    async (c) => {
      const body = c.req.valid("json");

      // 1. Validate schema exists and credentialSubject matches
      validator.validateOrThrow(body.schema, body.credentialSubject);

      // 2. Validate revocationRegistryUrl is a parseable HTTPS URL
      validateRevocationUrl(body.revocationRegistryUrl);

      // 3. Build the unsigned credential
      const builder = new CredentialBuilder()
        .setIssuer(body.issuer)
        .setCredentialSubject(body.credentialSubject)
        .setValidFrom(body.validFrom)
        .setCredentialStatus({
          id: body.revocationRegistryUrl,
          type: "DeDiRevocationListStatusV1",
          statusPurpose: "revocation",
        });

      if (body.validUntil) {
        builder.setValidUntil(body.validUntil);
      }

      const unsignedCredential = builder.build();

      // 4. Prepare the proof — compute dataToSign
      const verificationMethod = `${body.issuer}#${body.publicKey}`;
      const prepared = await prepareProof(unsignedCredential, {
        verificationMethod,
        proofPurpose: "assertionMethod",
      });

      // 5. Store session
      const sessionId = randomUUID();
      sessionStore.set(sessionId, {
        unsignedCredential,
        proofConfig: prepared.proofConfig,
        publicKey: body.publicKey,
        dataToSign: prepared.dataToSign,
      });

      // 6. Encode dataToSign as base64url
      const dataToSignBase64url = base64urlEncode(prepared.dataToSign);

      return c.json(
        {
          sessionId,
          unsignedCredential,
          dataToSign: dataToSignBase64url,
          proofConfig: prepared.proofConfig,
        },
        201,
      );
    },
  );

  // -----------------------------------------------------------------------
  // POST /credentials/package — Interface Signing phase 2
  // -----------------------------------------------------------------------
  credentials.post(
    "/package",
    authMiddleware(authOptions, "credentials:write"),
    zValidator("json", packageRequestSchema, (result, c) => {
      if (!result.success) {
        const fieldErrors = result.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        }));
        return c.json(
          {
            error: {
              code: "VALIDATION_ERROR",
              message: "Request validation failed",
              validationErrors: fieldErrors,
            },
          },
          400,
        );
      }
    }),
    async (c) => {
      const body = c.req.valid("json");

      // 1. Retrieve session
      const session = sessionStore.get(body.sessionId);
      if (!session) {
        throw new SessionExpiredError("Signing session not found or expired");
      }

      // 2. Decode signature from base64url
      let signatureBytes: Uint8Array;
      try {
        signatureBytes = base64urlDecode(body.signature);
      } catch {
        throw new ValidationError("Invalid base64url signature");
      }

      // 3. Validate signature length (P-256 ECDSA = 64 bytes r||s)
      if (signatureBytes.length !== 64) {
        throw new ValidationError("Invalid signature: expected 64 bytes (P-256 ECDSA r||s format)");
      }

      // 4. Assemble the final credential with proof
      const credential = completeProof(
        session.unsignedCredential,
        session.proofConfig,
        signatureBytes,
      );

      // 5. Consume the session (one-time use)
      sessionStore.delete(body.sessionId);

      return c.json(
        {
          credential,
          formats: {
            jsonld: credential,
          },
        },
        200,
      );
    },
  );

  return { credentials, sessionStore };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function validateRevocationUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ValidationError("Invalid revocationRegistryUrl: must be a valid URL");
  }
  if (parsed.protocol !== "https:") {
    throw new ValidationError("revocationRegistryUrl must use HTTPS");
  }
}

function base64urlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
