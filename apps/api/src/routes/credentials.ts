import { Hono } from "hono";
import { z } from "zod";
import { zValidator } from "@hono/zod-validator";
import { randomUUID } from "node:crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import type { UnsignedCredential } from "@opencred/vc-core";
import {
  prepareProof,
  completeProof,
  prepareJwsProof,
  completeJwsProof,
  prepareEdDsaProof,
  completeEdDsaProof,
  prepareVcJwtProof,
  completeVcJwtProof,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
  defaultProofFormat,
} from "@opencred/crypto";
import type { ProofConfig, SigningAlgorithm, ProofFormat } from "@opencred/crypto";
import { createRegistry, Validator } from "@opencred/schema-engine";
import { TTLStore } from "@opencred/state";
import { ValidationError, SessionExpiredError } from "@opencred/shared";
import type { EnvConfig } from "@opencred/shared";
import { authMiddleware, type AuthMiddlewareOptions } from "../middleware/auth.js";
import { packageFormats } from "../output/index.js";

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
  keyAlgorithm: z.enum(["P-256", "P-384", "RSA-2048", "RSA-3072", "RSA-4096", "Ed25519"]).optional(),
  dscCertificateChain: z.array(z.string().min(1)).optional(),
  proofFormat: z.enum(["data-integrity", "eddsa-di", "jws", "vc-jwt", "sd-jwt-vc"]).optional(),
  selectiveDisclosureClaims: z.array(z.string()).optional(),
  vct: z.string().optional(),
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
  proofConfig?: ProofConfig;
  publicKey: string;
  dataToSign: Uint8Array;
  proofMechanism: ProofFormat;
  jwsSigningInput?: string;
  dscCertificateChain?: string[];
  sdJwtVcDisclosures?: string[];
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
    authMiddleware(authOptions, "credentials:build"),
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

      // 4. Determine proof mechanism from key algorithm and optional proofFormat
      const keyAlgorithm = body.keyAlgorithm as SigningAlgorithm | undefined;
      const proofFormat: ProofFormat = (body.proofFormat as ProofFormat | undefined)
        ?? defaultProofFormat(keyAlgorithm ?? "P-256");
      const verificationMethod = `did:jwk:${body.publicKey}#0`;

      const sessionId = randomUUID();

      if (proofFormat === "sd-jwt-vc") {
        if (!body.selectiveDisclosureClaims || !body.vct) {
          throw new ValidationError("selectiveDisclosureClaims and vct are required for sd-jwt-vc format");
        }
        const sdPrepared = prepareSdJwtVcProof(unsignedCredential, keyAlgorithm ?? "P-256", {
          selectiveDisclosureClaims: body.selectiveDisclosureClaims,
          vct: body.vct,
          verificationMethod,
        });

        const signingInputBytes = new TextEncoder().encode(sdPrepared.signingInput);
        sessionStore.set(sessionId, {
          unsignedCredential,
          publicKey: body.publicKey,
          dataToSign: signingInputBytes,
          proofMechanism: "sd-jwt-vc",
          jwsSigningInput: sdPrepared.signingInput,
          sdJwtVcDisclosures: sdPrepared.disclosures,
          dscCertificateChain: body.dscCertificateChain,
        });

        return c.json(
          {
            sessionId,
            unsignedCredential,
            dataToSign: base64urlEncode(signingInputBytes),
            proofMechanism: "sd-jwt-vc" as const,
            disclosures: sdPrepared.disclosures,
          },
          201,
        );
      }

      if (proofFormat === "vc-jwt") {
        const vcJwtPrepared = prepareVcJwtProof(unsignedCredential as unknown as Record<string, unknown>, keyAlgorithm ?? "P-256", {
          verificationMethod,
        });

        const signingInputBytes = new TextEncoder().encode(vcJwtPrepared.signingInput);
        sessionStore.set(sessionId, {
          unsignedCredential,
          publicKey: body.publicKey,
          dataToSign: signingInputBytes,
          proofMechanism: "vc-jwt",
          jwsSigningInput: vcJwtPrepared.signingInput,
          dscCertificateChain: body.dscCertificateChain,
        });

        return c.json(
          {
            sessionId,
            unsignedCredential,
            dataToSign: base64urlEncode(signingInputBytes),
            proofMechanism: "vc-jwt" as const,
            protectedHeader: vcJwtPrepared.protectedHeader,
          },
          201,
        );
      }

      if (proofFormat === "jws") {
        // JWS enveloping proofs
        const jwsPrepared = prepareJwsProof(unsignedCredential, keyAlgorithm ?? "RSA-2048", {
          verificationMethod,
        });

        const signingInputBytes = new TextEncoder().encode(jwsPrepared.signingInput);
        sessionStore.set(sessionId, {
          unsignedCredential,
          publicKey: body.publicKey,
          dataToSign: signingInputBytes,
          proofMechanism: "jws",
          jwsSigningInput: jwsPrepared.signingInput,
          dscCertificateChain: body.dscCertificateChain,
        });

        return c.json(
          {
            sessionId,
            unsignedCredential,
            dataToSign: base64urlEncode(signingInputBytes),
            proofMechanism: "jws" as const,
            protectedHeader: jwsPrepared.protectedHeader,
          },
          201,
        );
      }

      if (proofFormat === "eddsa-di") {
        // EdDSA Data Integrity (eddsa-rdfc-2022)
        const prepared = await prepareEdDsaProof(unsignedCredential, {
          verificationMethod,
          proofPurpose: "assertionMethod",
        });

        sessionStore.set(sessionId, {
          unsignedCredential,
          proofConfig: prepared.proofConfig,
          publicKey: body.publicKey,
          dataToSign: prepared.dataToSign,
          proofMechanism: "eddsa-di",
          dscCertificateChain: body.dscCertificateChain,
        });

        return c.json(
          {
            sessionId,
            unsignedCredential,
            dataToSign: base64urlEncode(prepared.dataToSign),
            proofConfig: prepared.proofConfig,
            proofMechanism: "eddsa-di" as const,
          },
          201,
        );
      }

      // Default: Data Integrity (ecdsa-rdfc-2019) for EC keys
      const prepared = await prepareProof(unsignedCredential, {
        verificationMethod,
        proofPurpose: "assertionMethod",
      }, keyAlgorithm ?? "P-256");

      sessionStore.set(sessionId, {
        unsignedCredential,
        proofConfig: prepared.proofConfig,
        publicKey: body.publicKey,
        dataToSign: prepared.dataToSign,
        proofMechanism: "data-integrity",
        dscCertificateChain: body.dscCertificateChain,
      });

      const dataToSignBase64url = base64urlEncode(prepared.dataToSign);

      return c.json(
        {
          sessionId,
          unsignedCredential,
          dataToSign: dataToSignBase64url,
          proofConfig: prepared.proofConfig,
          proofMechanism: "data-integrity" as const,
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
    authMiddleware(authOptions, "credentials:build"),
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

      // 3. Assemble the final output based on proof mechanism
      let credential: unknown;

      if (session.proofMechanism === "jws") {
        if (!session.jwsSigningInput) {
          throw new ValidationError("JWS signing session is corrupted");
        }
        credential = completeJwsProof(session.jwsSigningInput, signatureBytes);
      } else if (session.proofMechanism === "vc-jwt") {
        if (!session.jwsSigningInput) {
          throw new ValidationError("VC-JWT signing session is corrupted");
        }
        credential = completeVcJwtProof(session.jwsSigningInput, signatureBytes);
      } else if (session.proofMechanism === "sd-jwt-vc") {
        if (!session.jwsSigningInput || !session.sdJwtVcDisclosures) {
          throw new ValidationError("SD-JWT VC signing session is corrupted");
        }
        credential = completeSdJwtVcProof(session.jwsSigningInput, signatureBytes, session.sdJwtVcDisclosures);
      } else if (session.proofMechanism === "eddsa-di") {
        if (signatureBytes.length !== 64) {
          throw new ValidationError(
            "Invalid signature: expected 64 bytes for Ed25519",
          );
        }
        if (!session.proofConfig) {
          throw new ValidationError("EdDSA Data Integrity signing session is corrupted");
        }
        credential = completeEdDsaProof(
          session.unsignedCredential,
          session.proofConfig,
          signatureBytes,
        );
      } else {
        // data-integrity (EC)
        if (signatureBytes.length !== 64 && signatureBytes.length !== 96) {
          throw new ValidationError(
            "Invalid signature: expected 64 bytes (P-256) or 96 bytes (P-384) ECDSA r||s format",
          );
        }
        if (!session.proofConfig) {
          throw new ValidationError("Data Integrity signing session is corrupted");
        }
        credential = completeProof(
          session.unsignedCredential,
          session.proofConfig,
          signatureBytes,
        );
      }

      // 5. Consume the session (one-time use)
      sessionStore.delete(body.sessionId);

      // 6. Generate QR + PDF output formats
      const formats = await packageFormats(credential as Record<string, unknown>);

      // 7. Include certificate chain if available
      const response: Record<string, unknown> = { credential, formats };
      if (session.dscCertificateChain && session.dscCertificateChain.length > 0) {
        response.dscCertificateChain = session.dscCertificateChain;
      }

      return c.json(response, 200);
    },
  );

  // 405 for non-POST methods
  for (const path of ["/build", "/package"]) {
    credentials.all(path, (c) => {
      if (c.req.method === "POST") return c.notFound();
      return c.json({ error: { code: "METHOD_NOT_ALLOWED", message: "Use POST" } }, 405);
    });
  }

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
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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
