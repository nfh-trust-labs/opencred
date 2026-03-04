import { Hono } from "hono";
import { z } from "zod";
import { zValidator } from "@hono/zod-validator";
import { randomUUID } from "node:crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import type { UnsignedCredential } from "@opencred/vc-core";
import {
  prepareProof,
  completeProof,
  signCredentialAuto,
  prepareJwsProof,
  completeJwsProof,
  computeRevocationHash,
} from "@opencred/crypto";
import type { ProofConfig, SigningKeyProvider, SigningAlgorithm } from "@opencred/crypto";
import { createRegistry, Validator } from "@opencred/schema-engine";
import { TTLStore } from "@opencred/state";
import { ValidationError, SessionExpiredError, AuthorizationError } from "@opencred/shared";
import type { EnvConfig } from "@opencred/shared";
import type { DeDiClient } from "@opencred/dedi-client";
import {
  resolveDelegation,
  validateDelegationCertificate,
  embedDelegation,
} from "@opencred/delegation";
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
  keyAlgorithm: z.enum(["P-256", "P-384", "RSA-2048", "RSA-3072", "RSA-4096"]).optional(),
  dscCertificateChain: z.array(z.string().min(1)).optional(),
});

const packageRequestSchema = z.object({
  sessionId: z.string().uuid("sessionId must be a valid UUID"),
  signature: z.string().min(1, "signature is required"),
});

const issueDelegatedRequestSchema = z.object({
  delegationId: z.string().min(1, "delegationId is required"),
  schema: z.string().min(1, "schema is required"),
  credentialSubject: z.record(z.unknown()).refine((v) => Object.keys(v).length > 0, {
    message: "credentialSubject must not be empty",
  }),
  validFrom: z.string().min(1, "validFrom is required"),
  validUntil: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Session store types
// ---------------------------------------------------------------------------

interface SigningSession {
  unsignedCredential: UnsignedCredential;
  proofConfig?: ProofConfig;
  publicKey: string;
  dataToSign: Uint8Array;
  proofMechanism: "data-integrity" | "jws";
  jwsSigningInput?: string;
  dscCertificateChain?: string[];
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export interface CredentialsRouteDeps {
  config: EnvConfig;
  authOptions: AuthMiddlewareOptions;
  signingKeyProvider?: SigningKeyProvider;
  dediClient?: DeDiClient;
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

      // 4. Determine proof mechanism from key algorithm
      const keyAlgorithm = body.keyAlgorithm as SigningAlgorithm | undefined;
      const isRsa = keyAlgorithm?.startsWith("RSA");
      const verificationMethod = `${body.issuer}#${body.publicKey}`;

      const sessionId = randomUUID();

      if (isRsa) {
        // RSA keys use VC-JOSE-COSE JWS enveloping proofs
        const jwsPrepared = prepareJwsProof(unsignedCredential, keyAlgorithm!, {
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

      // EC keys use Data Integrity embedded proofs
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
      } else {
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

  // -----------------------------------------------------------------------
  // POST /credentials/issue-delegated — Delegated Signing
  // -----------------------------------------------------------------------
  if (deps.signingKeyProvider && deps.dediClient) {
    const { signingKeyProvider, dediClient } = deps;

    // Derive DeDi base URL from config, falling back to a safe default
    const dediBaseUrl = config.DEDI_API_URL ?? "https://dedi.example";

    credentials.post(
      "/issue-delegated",
      authMiddleware(authOptions, "credentials:issue-delegated"),
      zValidator("json", issueDelegatedRequestSchema, (result, c) => {
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

        // 1. Resolve delegation certificate from DeDi
        const delegation = await resolveDelegation(dediClient, {
          delegationId: body.delegationId,
        });

        // 2. Validate delegation: active, scope, not expired
        const validationResult = await validateDelegationCertificate(delegation, {
          credentialType: body.schema,
        });

        if (!validationResult.valid) {
          if (validationResult.status === "expired") {
            throw new AuthorizationError(
              `Delegation certificate has expired: ${validationResult.errors.join("; ")}`,
            );
          }
          if (validationResult.status === "revoked") {
            throw new AuthorizationError(
              `Delegation certificate has been revoked: ${validationResult.errors.join("; ")}`,
            );
          }
          // Scope mismatch or other validation failure
          throw new AuthorizationError(
            `Delegation validation failed: ${validationResult.errors.join("; ")}`,
          );
        }

        // 3. Check revocation status against DeDi registry
        const revocationHash = computeRevocationHash({ delegationId: body.delegationId });
        const revocationRecord = await dediClient.queryRevocationHash(revocationHash);
        if (revocationRecord.revoked) {
          throw new AuthorizationError("Delegation has been revoked");
        }

        // 4. Validate delegatee matches the current signing key
        const activeKey = signingKeyProvider.getActiveKey();
        if (delegation.delegatee.id !== activeKey.id) {
          throw new AuthorizationError("Delegation does not authorize the current signing key");
        }

        // 5. Validate schema exists and credentialSubject matches
        validator.validateOrThrow(body.schema, body.credentialSubject);

        // 6. Build unsigned VC — issuer is the delegation's delegator
        const issuer = delegation.delegator.name
          ? { id: delegation.delegator.id, name: delegation.delegator.name }
          : delegation.delegator.id;

        const builder = new CredentialBuilder()
          .setIssuer(issuer)
          .setCredentialSubject(body.credentialSubject)
          .setValidFrom(body.validFrom)
          .setCredentialStatus({
            id: `${dediBaseUrl}/revocations/${encodeURIComponent(delegation.delegator.id)}/registry`,
            type: "DeDiRevocationListStatusV1",
            statusPurpose: "revocation",
          });

        if (body.validUntil) {
          builder.setValidUntil(body.validUntil);
        }

        const unsignedCredential = builder.build();

        // 7. Sign with OpenCred's active key (auto-dispatches EC → DI, RSA → JWS)
        const signedCredential = await signCredentialAuto(unsignedCredential, activeKey, {
          verificationMethod: activeKey.id,
          proofPurpose: "assertionMethod",
        });

        // 8. Embed delegation reference in the credential (DI only)
        const credentialWithDelegation = typeof signedCredential === "string"
          ? signedCredential // JWS: delegation metadata not embedded in compact string
          : embedDelegation(signedCredential, delegation);

        // 9. Generate QR + PDF output formats
        const formats = await packageFormats(
          credentialWithDelegation as unknown as Record<string, unknown>,
        );

        // 10. Compute credential hash for revocation tracking
        const credentialHash = computeRevocationHash(credentialWithDelegation);

        return c.json({ credential: credentialWithDelegation, credentialHash, formats }, 201);
      },
    );
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
