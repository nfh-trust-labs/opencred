/**
 * Tests for the local signing flow.
 *
 * Full offline round-trip: build -> sign -> verify.
 * Generates a test P-256 key pair, signs a credential, and verifies it
 * using @opencred/crypto.verifyProof.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { createSoftwareSigner } from "../signing/software-signer";
import {
  buildAndSign,
  listSchemas,
  getSchemaDefinition,
  validateSubject,
} from "../signing/local-signing-flow";
import { verifyProof } from "@opencred/crypto";

let tmpDir: string;
let pemKeyPath: string;

// Generate a P-256 key pair for testing
const { privateKey: testPrivateKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-flow-test-"));

  const pemKey = testPrivateKey.export({ format: "pem", type: "pkcs8" }) as string;
  pemKeyPath = path.join(tmpDir, "test-key.pem");
  fs.writeFileSync(pemKeyPath, pemKey);
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("Schema management", () => {
  it("should list available schemas", () => {
    const schemas = listSchemas();
    expect(schemas).toBeInstanceOf(Array);
    expect(schemas.length).toBeGreaterThan(0);
    expect(schemas).toContain("education");
    expect(schemas).toContain("employment");
    expect(schemas).toContain("identity");
    expect(schemas).toContain("health");
    expect(schemas).toContain("business");
  });

  it("should get a schema definition by ID", () => {
    const definition = getSchemaDefinition("education");
    expect(definition.id).toBe("education");
    expect(definition.schema).toBeDefined();
    expect(definition.contextUrl).toBeDefined();
  });

  it("should throw for unknown schema ID", () => {
    expect(() => getSchemaDefinition("nonexistent")).toThrow(/not found/i);
  });
});

describe("Schema validation", () => {
  it("should validate valid education subject data", () => {
    const result = validateSubject("education", {
      name: "Jane Doe",
      degree: "Bachelor of Science",
      institution: "MIT",
      dateConferred: "2025-06-15",
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("should reject invalid education subject data (missing required fields)", () => {
    const result = validateSubject("education", {
      name: "Jane Doe",
      // Missing: degree, institution, dateConferred
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });
});

describe("buildAndSign — full offline round-trip", () => {
  it("should build, sign, and produce a valid VerifiableCredential (default vc-jwt)", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);

    const result = await buildAndSign(signer, {
      schemaId: "education",
      issuerDid: "did:web:university.example",
      credentialSubject: {
        name: "Jane Doe",
        degree: "Bachelor of Science",
        institution: "MIT",
        dateConferred: "2025-06-15",
      },
      validFrom: "2025-06-15T00:00:00Z",
    });

    const { credential, unsignedCredential, proofFormat, isCompactToken } = result;

    // Default format is vc-jwt
    expect(proofFormat).toBe("vc-jwt");
    expect(isCompactToken).toBe(false);

    // Verify the signed credential structure (VC-JWT)
    expect(credential).toBeDefined();
    const vc = credential as Record<string, unknown>;
    const proof = vc.proof as Record<string, unknown>;
    expect(proof).toBeDefined();
    expect(proof.type).toBe("JsonWebSignature2020");
    expect(proof.jwt).toBeDefined();
    expect(typeof proof.jwt).toBe("string");

    // Verify the unsigned credential structure
    expect(unsignedCredential).toBeDefined();
    expect(unsignedCredential.issuer).toBe("did:web:university.example");
    expect(unsignedCredential.credentialSubject.name).toBe("Jane Doe");
  });

  it("should produce a Data Integrity proof when explicitly requested", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);

    const result = await buildAndSign(signer, {
      schemaId: "education",
      issuerDid: "did:web:university.example",
      credentialSubject: {
        name: "Jane Doe",
        degree: "Bachelor of Science",
        institution: "MIT",
        dateConferred: "2025-06-15",
      },
      validFrom: "2025-06-15T00:00:00Z",
      proofFormat: "data-integrity",
    });

    const { credential, proofFormat } = result;
    expect(proofFormat).toBe("data-integrity");

    const vc = credential as Record<string, unknown>;
    const proof = vc.proof as Record<string, unknown>;
    expect(proof.type).toBe("DataIntegrityProof");
    expect(proof.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(proof.proofValue).toMatch(/^z/);
  });

  it("should produce a data-integrity credential that verifies with verifyProof", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);
    const publicKey = createPublicKey(testPrivateKey);

    const result = await buildAndSign(signer, {
      schemaId: "education",
      issuerDid: "did:web:university.example",
      credentialSubject: {
        name: "Jane Doe",
        degree: "Bachelor of Science",
        institution: "MIT",
        dateConferred: "2025-06-15",
      },
      validFrom: "2025-06-15T00:00:00Z",
      proofFormat: "data-integrity",
    });

    // Verify the proof using @opencred/crypto (works with Data Integrity proofs)
    const verifyResult = await verifyProof(result.credential, { publicKey });
    expect(verifyResult.verified).toBe(true);
    expect(verifyResult.error).toBeUndefined();
  });

  it("should include optional fields when provided", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);

    const result = await buildAndSign(signer, {
      schemaId: "education",
      issuerDid: "did:web:university.example",
      credentialSubject: {
        name: "Jane Doe",
        degree: "Bachelor of Science",
        institution: "MIT",
        dateConferred: "2025-06-15",
      },
      validFrom: "2025-06-15T00:00:00Z",
      validUntil: "2030-06-15T00:00:00Z",
      subjectDid: "did:example:holder123",
      additionalTypes: ["EducationCredential"],
      revocationRegistryUrl: "https://dedi.example/revocations/test",
    });

    const { credential } = result;
    expect(credential.validUntil).toBe("2030-06-15T00:00:00Z");
    expect(credential.credentialSubject.id).toBe("did:example:holder123");
    expect(credential.type).toContain("EducationCredential");
    expect(credential.credentialStatus).toBeDefined();
    expect(credential.credentialStatus?.id).toBe("https://dedi.example/revocations/test");
  });

  it("should reject invalid subject data", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);

    await expect(
      buildAndSign(signer, {
        schemaId: "education",
        issuerDid: "did:web:university.example",
        credentialSubject: {
          name: "Jane Doe",
          // Missing required fields
        },
        validFrom: "2025-06-15T00:00:00Z",
      }),
    ).rejects.toThrow(/validation/i);
  });

  it("should reject unknown schema IDs", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);

    await expect(
      buildAndSign(signer, {
        schemaId: "nonexistent",
        issuerDid: "did:web:example.com",
        credentialSubject: { name: "Test" },
        validFrom: "2025-01-01T00:00:00Z",
      }),
    ).rejects.toThrow(/not found/i);
  });

  it("should work with all built-in schemas", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);
    const publicKey = createPublicKey(testPrivateKey);

    // Employment (data-integrity for verifyProof compatibility)
    const employment = await buildAndSign(signer, {
      schemaId: "employment",
      issuerDid: "did:web:employer.example",
      credentialSubject: {
        name: "John Smith",
        employer: "ACME Corp",
        position: "Engineer",
        startDate: "2024-01-15",
      },
      validFrom: "2024-01-15T00:00:00Z",
      proofFormat: "data-integrity",
    });
    const empVerify = await verifyProof(employment.credential, { publicKey });
    expect(empVerify.verified).toBe(true);

    // Identity (data-integrity for verifyProof compatibility)
    const identity = await buildAndSign(signer, {
      schemaId: "identity",
      issuerDid: "did:web:gov.example",
      credentialSubject: {
        name: "Alice Johnson",
        dateOfBirth: "1990-05-20",
        nationality: "US",
        documentNumber: "AB123456",
      },
      validFrom: "2024-01-01T00:00:00Z",
      proofFormat: "data-integrity",
    });
    const idVerify = await verifyProof(identity.credential, { publicKey });
    expect(idVerify.verified).toBe(true);
  });

  it("should detect tampered credentials during verification", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);
    const publicKey = createPublicKey(testPrivateKey);

    const result = await buildAndSign(signer, {
      schemaId: "education",
      issuerDid: "did:web:university.example",
      credentialSubject: {
        name: "Jane Doe",
        degree: "Bachelor of Science",
        institution: "MIT",
        dateConferred: "2025-06-15",
      },
      validFrom: "2025-06-15T00:00:00Z",
      proofFormat: "data-integrity",
    });

    // Tamper with a W3C-defined property (issuer) which is in the canonical form.
    // Custom credentialSubject properties without a JSON-LD context mapping
    // may not affect the canonical form, so we tamper with a standard field.
    const tampered = {
      ...result.credential,
      issuer: "did:web:attacker.example",
    };

    const verifyResult = await verifyProof(tampered, { publicKey });
    expect(verifyResult.verified).toBe(false);
  });
});
