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
import { CredentialBuilder } from "@opencred/vc-core";
import type { VerifiableCredential } from "@opencred/vc-core";
import { createRegistry, Validator } from "@opencred/schema-engine";
import type { SchemaRegistry } from "@opencred/schema-engine";
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
import { CryptoError } from "@opencred/shared";
import { requireSigner } from "../signing/key-manager.js";
import { packageCredential } from "../packaging/packager.js";
import type { PackageFormat } from "../packaging/packager.js";

const credentials = new Hono();

// Singleton schema registry and validator
let registryInstance: SchemaRegistry | null = null;
let validatorInstance: Validator | null = null;

function getRegistry(): SchemaRegistry {
  if (!registryInstance) {
    registryInstance = createRegistry();
  }
  return registryInstance;
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
  subjectDid: z.string().optional(),
  selectiveDisclosureClaims: z.array(z.string()).optional(),
  revocationRegistryUrl: z.string().url().optional(),
  credentialSchemaUrl: z.string().url().optional(),
  packageFormats: z.array(z.enum(["qr-png", "qr-svg", "pdf", "json-ld", "json-compact"])).optional(),
});

const verifyRequestSchema = z.object({
  credential: z.string(),
});

// --- Issue endpoint ---

credentials.post("/credentials/issue", async (c) => {
  const body = await c.req.json();
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
  if (parsed.credentialSchemaUrl) {
    builder.setSchema({ id: parsed.credentialSchemaUrl, type: "JsonSchema" });
  }

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
  }

  // Package if formats requested (only for JSON-based credentials, not compact tokens)
  let packagedOutputs: Array<{ format: string; data: string; mimeType: string; suggestedFileName: string; encoding: string }> | undefined;
  if (!isCompactToken && parsed.packageFormats && parsed.packageFormats.length > 0) {
    const credential = JSON.parse(signedOutput) as Parameters<typeof packageCredential>[0];
    const result = await packageCredential(credential, parsed.packageFormats as PackageFormat[]);
    packagedOutputs = result.outputs.map((output) => ({
      format: output.format,
      data: Buffer.isBuffer(output.data) ? output.data.toString("base64") : output.data,
      mimeType: output.mimeType,
      suggestedFileName: output.suggestedFileName,
      encoding: Buffer.isBuffer(output.data) ? "base64" : "utf-8",
    }));
  }

  return c.json({
    credential: isCompactToken ? signedOutput : JSON.parse(signedOutput),
    proofFormat,
    isCompactToken,
    packagedOutputs,
  });
});

// --- Verify endpoint ---

credentials.post("/credentials/verify", async (c) => {
  const body = await c.req.json();
  const parsed = verifyRequestSchema.parse(body);

  const credential = JSON.parse(parsed.credential);

  // Verify using composite DID resolver (supports did:key, did:jwk, did:web)
  const { DIDKeyResolver, DIDJwkResolver, DIDWebResolver, CompositeDIDResolver } = await import("@opencred/did");
  const { verifyCredential } = await import("@opencred/verification");

  const compositeResolver = new CompositeDIDResolver(
    new Map([
      ["key", new DIDKeyResolver()],
      ["jwk", new DIDJwkResolver()],
      ["web", new DIDWebResolver()],
    ]),
  );

  const verificationResult = await verifyCredential(credential, {
    didResolver: compositeResolver,
  });

  return c.json({
    valid: verificationResult.verified,
    message: verificationResult.verified
      ? "Credential is valid."
      : (verificationResult.checks.find((check) => !check.passed)?.detail ?? "Verification failed."),
    checks: verificationResult.checks,
  });
});

export { credentials };
