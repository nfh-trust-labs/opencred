import { Hono } from "hono";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { createPublicKey, createVerify, type KeyObject } from "node:crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import { prepareProof, completeProof } from "@opencred/crypto";
import type { ProofConfig } from "@opencred/crypto";
import { createRegistry, Validator } from "@opencred/schema-engine";
import { TTLStore } from "@opencred/state";
import { ValidationError, SessionExpiredError } from "@opencred/shared";
import type { UnsignedCredential } from "@opencred/vc-core";

// --- Zod schemas for request validation ---

const jwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: z.string().min(1),
    y: z.string().min(1),
  })
  .passthrough();

const buildRequestSchema = z.object({
  schema: z.string().min(1, "schema is required"),
  issuer: z.string().min(1, "issuer DID is required"),
  publicKey: jwkSchema,
  credentialSubject: z
    .record(z.unknown())
    .refine((val) => Object.keys(val).length > 0, "credentialSubject must not be empty"),
  validFrom: z.string().min(1, "validFrom is required"),
  validUntil: z.string().optional(),
  revocationRegistryUrl: z.string().optional(),
  verificationMethod: z.string().optional(),
});

const packageRequestSchema = z.object({
  sessionId: z.string().uuid("sessionId must be a valid UUID"),
  signature: z.string().min(1, "signature is required"),
});

// --- Session type ---

export interface SigningSession {
  unsignedCredential: UnsignedCredential;
  dataToSign: Uint8Array;
  proofConfig: ProofConfig;
  publicKeyJwk: { kty: string; crv: string; x: string; y: string; [key: string]: unknown };
}

// --- Factory ---

export interface SigningRoutesDeps {
  sessionStore: TTLStore<SigningSession>;
}

export function createSigningRoutes(deps: SigningRoutesDeps) {
  const { sessionStore } = deps;
  const registry = createRegistry();
  const validator = new Validator(registry);
  const signing = new Hono();

  // POST /build — Interface Signing step 1
  signing.post("/build", async (c) => {
    const rawBody = await c.req.json();
    const parsed = buildRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const {
      schema,
      issuer,
      publicKey,
      credentialSubject,
      validFrom,
      validUntil,
      revocationRegistryUrl,
      verificationMethod,
    } = parsed.data;

    // 1. Validate schema + credentialSubject
    validator.validateOrThrow(schema, credentialSubject);

    // 2. Validate revocationRegistryUrl if provided
    if (revocationRegistryUrl) {
      validateRevocationUrl(revocationRegistryUrl);
    }

    // 3. Build unsigned VC
    const builder = new CredentialBuilder()
      .setIssuer(issuer)
      .setCredentialSubject(credentialSubject)
      .setValidFrom(validFrom);

    if (validUntil) {
      builder.setValidUntil(validUntil);
    }

    // Set credential schema reference (JSON Schema $id URL, not JSON-LD context)
    const schemaDef = registry.getSchema(schema);
    const schemaId = (schemaDef.schema.$id as string | undefined) ?? schemaDef.id;
    builder.setSchema({ id: schemaId, type: "JsonSchema" });

    if (revocationRegistryUrl) {
      builder.setCredentialStatus({
        id: revocationRegistryUrl,
        type: "DeDiRevocationListStatusV1",
        statusPurpose: "revocation",
      });
    }

    const unsignedVC = builder.build();

    // 4. Prepare proof / compute dataToSign
    const vm = verificationMethod ?? `${issuer}#key-0`;
    const prepared = await prepareProof(unsignedVC, {
      verificationMethod: vm,
      proofPurpose: "assertionMethod",
    });

    // 5. Store session in TTL store
    const sessionId = randomUUID();
    sessionStore.set(sessionId, {
      unsignedCredential: unsignedVC,
      dataToSign: prepared.dataToSign,
      proofConfig: prepared.proofConfig,
      publicKeyJwk: publicKey,
    });

    // 6. Return response
    const dataToSignB64 = bufferToBase64Url(prepared.dataToSign);
    return c.json(
      {
        sessionId,
        unsignedCredential: unsignedVC,
        dataToSign: dataToSignB64,
        proofConfig: prepared.proofConfig,
      },
      201,
    );
  });

  // POST /package — Interface Signing step 2
  signing.post("/package", async (c) => {
    const rawBody = await c.req.json();
    const parsed = packageRequestSchema.safeParse(rawBody);
    if (!parsed.success) {
      const firstError = parsed.error.issues[0];
      throw new ValidationError(`${firstError.path.join(".")}: ${firstError.message}`);
    }

    const { sessionId, signature } = parsed.data;

    // 1. Retrieve session from TTL store
    const session = sessionStore.get(sessionId);
    if (!session) {
      throw new SessionExpiredError("Signing session not found or expired");
    }

    // 2. Decode signature from base64url
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = base64UrlToBuffer(signature);
    } catch {
      throw new ValidationError("Invalid base64url signature");
    }

    if (signatureBytes.length !== 64) {
      throw new ValidationError("Signature must be 64 bytes (r || s for P-256 ECDSA)");
    }

    // 3. Validate signature against stored public key BEFORE packaging
    const pubKey = importJwkPublicKey(session.publicKeyJwk);
    const signatureValid = verifySignature(pubKey, session.dataToSign, signatureBytes);
    if (!signatureValid) {
      throw new ValidationError("Signature verification failed");
    }

    // 4. Assemble final proof
    const vc = completeProof(session.unsignedCredential, session.proofConfig, signatureBytes);

    // 5. Remove session (one-time use)
    sessionStore.delete(sessionId);

    // 6. Return packaged VC
    return c.json({
      credential: vc,
      formats: { jsonld: vc },
    });
  });

  return signing;
}

// --- Helpers ---

function validateRevocationUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ValidationError("Invalid revocation registry URL: must be a valid URL");
  }
  if (parsed.protocol !== "https:") {
    throw new ValidationError("Revocation registry URL must use HTTPS");
  }
}

function bufferToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function base64UrlToBuffer(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64url"));
}

function importJwkPublicKey(jwk: Record<string, unknown>): KeyObject {
  return createPublicKey({ key: jwk, format: "jwk" });
}

function verifySignature(
  publicKey: KeyObject,
  dataToSign: Uint8Array,
  signatureBytes: Uint8Array,
): boolean {
  const verifier = createVerify("SHA256");
  verifier.update(dataToSign);
  return verifier.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, signatureBytes);
}
