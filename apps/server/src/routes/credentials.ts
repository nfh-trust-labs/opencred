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
  verifyProof,
} from "@opencred/crypto";
import { publicKeyFromMultibase } from "@opencred/verification";
import { ValidationError, CryptoError } from "@opencred/shared";
import { requireSigner } from "../signing/key-manager.js";

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
    builder.setCredentialStatus({
      id: parsed.revocationRegistryUrl,
      type: "DeDiRevocationListStatusV1",
      statusPurpose: "revocation",
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

  return c.json({
    credential: isCompactToken ? signedOutput : JSON.parse(signedOutput),
    proofFormat,
    isCompactToken,
  });
});

// --- Verify endpoint ---

credentials.post("/credentials/verify", async (c) => {
  const body = await c.req.json();
  const parsed = verifyRequestSchema.parse(body);

  const credential = JSON.parse(parsed.credential);

  // Resolve public key from did:key
  const proof = credential.proof;
  if (!proof || !proof.verificationMethod) {
    throw new ValidationError("Credential is missing proof.verificationMethod");
  }

  const vm: string = proof.verificationMethod;
  const fragment = vm.includes("#") ? vm.split("#")[1] : undefined;
  let publicKey = undefined;
  if (fragment) {
    publicKey = publicKeyFromMultibase(fragment) ?? undefined;
  }

  if (!publicKey) {
    return c.json({
      valid: false,
      message: "Unable to resolve public key from verificationMethod. Only did:key is supported.",
      checks: [{ name: "key-resolution", passed: false, detail: "Could not resolve public key" }],
    });
  }

  const result = await verifyProof(credential, { publicKey });

  const checks: Array<{ name: string; passed: boolean; detail?: string }> = [
    { name: "signature", passed: result.verified, detail: result.error },
  ];

  // Date checks
  const now = new Date();
  if (credential.validFrom) {
    const validFrom = new Date(credential.validFrom);
    checks.push(
      validFrom > now
        ? { name: "not-before", passed: false, detail: `Not yet valid (validFrom: ${credential.validFrom})` }
        : { name: "not-before", passed: true },
    );
  }

  if (credential.validUntil) {
    const validUntil = new Date(credential.validUntil);
    checks.push(
      validUntil < now
        ? { name: "expiry", passed: false, detail: `Expired (validUntil: ${credential.validUntil})` }
        : { name: "expiry", passed: true },
    );
  }

  const allPassed = checks.every((check) => check.passed);

  return c.json({
    valid: allPassed,
    message: allPassed
      ? "Credential is valid."
      : (checks.find((check) => !check.passed)?.detail ?? "Verification failed."),
    checks,
  });
});

export { credentials };
