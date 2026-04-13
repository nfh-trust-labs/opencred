import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import type { UnsignedCredential } from "@opencred/vc-core";
import { signCredential, signCredentialVcJwt, signCredentialSdJwtVc } from "@opencred/crypto";
import type { SigningKey, VcJwtSigningOptions, SdJwtVcSigningOptions } from "@opencred/crypto";
import { verifyCredential } from "@opencred/verification";
import type { JWK } from "@opencred/did";
import { createMockResolver } from "./helpers.js";

const ISSUER_DID = "did:web:issuer.example";
const VM_ID = `${ISSUER_DID}#key-1`;

let privateKey: KeyObject;
let publicKey: KeyObject;
let publicKeyJwk: JWK;
let signingKey: SigningKey;

beforeAll(() => {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  privateKey = pair.privateKey;
  publicKey = pair.publicKey;
  publicKeyJwk = publicKey.export({ format: "jwk" }) as JWK;
  signingKey = { id: VM_ID, privateKey, publicKey, algorithm: "P-256" };
});

function buildTestCredential(): UnsignedCredential {
  return new CredentialBuilder()
    .setIssuer(ISSUER_DID)
    .setCredentialSubject({ id: "did:example:holder", name: "Jane Doe" })
    .setValidFrom("2026-01-01T00:00:00Z")
    .build();
}

describe("CredentialBuilder -> sign -> verify (package-level)", () => {
  it("data-integrity round-trip", async () => {
    const unsigned = buildTestCredential();
    const signed = await signCredential(unsigned, signingKey, {
      verificationMethod: VM_ID,
      proofPurpose: "assertionMethod",
      created: "2026-01-01T00:00:00Z",
    });

    const resolver = createMockResolver(ISSUER_DID, publicKeyJwk);
    const result = await verifyCredential(
      signed as unknown as Record<string, unknown>,
      { didResolver: resolver },
    );

    expect(result.code).toBe("VALID");
    expect(result.verified).toBe(true);
    expect(result.checks.some((c) => c.name === "signature" && c.passed)).toBe(true);
  });

  it("vc-jwt round-trip", async () => {
    const unsigned = buildTestCredential();
    const vcJwtOptions: VcJwtSigningOptions = { verificationMethod: VM_ID };
    const jwt = await signCredentialVcJwt(
      unsigned as unknown as Record<string, unknown>,
      signingKey,
      vcJwtOptions,
    );

    expect(typeof jwt).toBe("string");
    expect(jwt.split(".")).toHaveLength(3);

    const resolver = createMockResolver(ISSUER_DID, publicKeyJwk);
    const result = await verifyCredential(jwt, { didResolver: resolver });

    expect(result.code).toBe("VALID");
    expect(result.verified).toBe(true);
  });

  it("sd-jwt-vc round-trip", async () => {
    const unsigned = buildTestCredential();
    const sdJwtOptions: SdJwtVcSigningOptions = {
      selectiveDisclosureClaims: ["name"],
      vct: "VerifiableCredential",
      verificationMethod: VM_ID,
    };
    const sdJwt = await signCredentialSdJwtVc(unsigned, signingKey, sdJwtOptions);

    expect(typeof sdJwt).toBe("string");
    expect(sdJwt).toContain("~");

    const resolver = createMockResolver(ISSUER_DID, publicKeyJwk);
    const result = await verifyCredential(sdJwt, { didResolver: resolver });

    expect(result.code).toBe("VALID");
    expect(result.verified).toBe(true);
  });

  it("tamper detection — data-integrity", async () => {
    const unsigned = buildTestCredential();
    const signed = await signCredential(unsigned, signingKey, {
      verificationMethod: VM_ID,
      proofPurpose: "assertionMethod",
      created: "2026-01-01T00:00:00Z",
    });

    const tampered = {
      ...signed,
      credentialSubject: { ...signed.credentialSubject, name: "Mallory" },
    };

    const resolver = createMockResolver(ISSUER_DID, publicKeyJwk);
    const result = await verifyCredential(
      tampered as unknown as Record<string, unknown>,
      { didResolver: resolver },
    );

    expect(result.code).toBe("INVALID");
    expect(result.verified).toBe(false);
  });
});
