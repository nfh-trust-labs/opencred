import { describe, it, expect } from "vitest";
import {
  generateKeyPairSync,
  createSign,
  createVerify,
  verify as cryptoVerify,
  KeyObject,
} from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { JWS_2020_V1_CONTEXT } from "@opencred/vc-core";
import type { UnsignedCredential } from "@opencred/vc-core";
import {
  prepareJws2020Proof,
  completeJws2020Proof,
  signCredentialJws2020,
  ensureJws2020Context,
  jws2020ProtectedHeader,
  computeJws2020VerifyData,
  buildJws2020SigningInput,
} from "../jws-2020.js";
import type { Jws2020ProofConfig } from "../jws-2020.js";
import type { SigningKey, SigningAlgorithm } from "../types.js";

function createTestSigningKey(id: string, algorithm: SigningAlgorithm = "P-256"): SigningKey {
  let privateKey: KeyObject;
  let publicKey: KeyObject;
  if (algorithm === "Ed25519") {
    ({ privateKey, publicKey } = generateKeyPairSync("ed25519"));
  } else if (algorithm.startsWith("RSA")) {
    ({ privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 }));
  } else {
    ({ privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: algorithm === "P-384" ? "P-384" : "P-256",
    }));
  }
  return { id, privateKey, publicKey, algorithm };
}

function createTestCredential(): UnsignedCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:test-credential-jws2020-001",
    type: ["VerifiableCredential"],
    issuer: "did:web:university.example",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder123",
      name: "Jane Doe",
    },
  };
}

const VM = "did:web:university.example#key-1";
const defaultOptions = { verificationMethod: VM, proofPurpose: "assertionMethod" };

/**
 * Reference verification: rebuild the RFC 7797 signing input from the signed
 * credential and check the detached JWS signature with node:crypto.
 */
async function referenceVerify(
  signedVC: Record<string, unknown>,
  publicKey: KeyObject,
): Promise<boolean> {
  const proof = signedVC.proof as Record<string, unknown>;
  const jws = proof.jws as string;
  const [headerB64, detachedPayload, signatureB64] = jws.split(".");
  expect(detachedPayload).toBe("");

  const { proof: _proof, ...unsignedDoc } = signedVC;
  const proofConfig: Jws2020ProofConfig = {
    "@context": signedVC["@context"] as (string | Record<string, unknown>)[],
    type: "JsonWebSignature2020",
    created: proof.created as string,
    verificationMethod: proof.verificationMethod as string,
    proofPurpose: proof.proofPurpose as string,
  };
  const verifyData = await computeJws2020VerifyData(unsignedDoc, proofConfig);
  const signingInput = buildJws2020SigningInput(headerB64, verifyData);
  const signature = new Uint8Array(Buffer.from(signatureB64, "base64url"));

  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString()) as { alg: string };
  switch (header.alg) {
    case "ES256":
    case "ES384": {
      const verifier = createVerify(header.alg === "ES384" ? "SHA384" : "SHA256");
      verifier.update(signingInput);
      return verifier.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
    }
    case "EdDSA":
      return cryptoVerify(null, signingInput, publicKey, signature);
    case "PS256":
      return cryptoVerify(
        "sha256",
        signingInput,
        { key: publicKey, padding: 6 /* RSA_PKCS1_PSS_PADDING */, saltLength: 32 },
        signature,
      );
    default:
      throw new Error(`Unexpected alg ${header.alg}`);
  }
}

describe("signCredentialJws2020 — proof shape", () => {
  it("produces a JsonWebSignature2020 proof with a detached JWS", async () => {
    const signingKey = createTestSigningKey(VM);
    const signedVC = await signCredentialJws2020(
      createTestCredential(),
      signingKey,
      defaultOptions,
    );

    expect(signedVC.proof.type).toBe("JsonWebSignature2020");
    expect(signedVC.proof.proofPurpose).toBe("assertionMethod");
    expect(signedVC.proof.verificationMethod).toBe(VM);
    expect(signedVC.proof.created).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/,
    );
    // No Data Integrity fields on a JWS-2020 proof.
    expect(signedVC.proof.proofValue).toBeUndefined();
    expect(signedVC.proof.cryptosuite).toBeUndefined();

    const jws = signedVC.proof["jws"] as string;
    const parts = jws.split(".");
    expect(parts).toHaveLength(3);
    expect(parts[1]).toBe(""); // detached payload

    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    expect(header).toEqual({ alg: "ES256", b64: false, crit: ["b64"] });
  });

  it("appends the JWS-2020 suite context to @context", async () => {
    const signingKey = createTestSigningKey(VM);
    const signedVC = await signCredentialJws2020(
      createTestCredential(),
      signingKey,
      defaultOptions,
    );
    expect(signedVC["@context"]).toContain(JWS_2020_V1_CONTEXT);
  });

  it("does not duplicate the suite context when already present", async () => {
    const signingKey = createTestSigningKey(VM);
    const unsigned = createTestCredential();
    unsigned["@context"] = [...(unsigned["@context"] as string[]), JWS_2020_V1_CONTEXT];
    const signedVC = await signCredentialJws2020(unsigned, signingKey, defaultOptions);
    const occurrences = (signedVC["@context"] as string[]).filter((c) => c === JWS_2020_V1_CONTEXT);
    expect(occurrences).toHaveLength(1);
  });
});

describe("signCredentialJws2020 — round-trip verification", () => {
  it.each([
    ["P-256", "ES256"],
    ["P-384", "ES384"],
    ["Ed25519", "EdDSA"],
    ["RSA-2048", "PS256"],
  ] as const)("signs with %s and verifies (%s)", async (algorithm, expectedAlg) => {
    const signingKey = createTestSigningKey(VM, algorithm);
    const signedVC = await signCredentialJws2020(
      createTestCredential(),
      signingKey,
      defaultOptions,
    );

    const header = JSON.parse(
      Buffer.from((signedVC.proof["jws"] as string).split(".")[0], "base64url").toString(),
    );
    expect(header.alg).toBe(expectedAlg);

    const ok = await referenceVerify(
      signedVC as unknown as Record<string, unknown>,
      signingKey.publicKey,
    );
    expect(ok).toBe(true);
  });

  it("fails reference verification when the credential is tampered with", async () => {
    const signingKey = createTestSigningKey(VM);
    const signedVC = await signCredentialJws2020(
      createTestCredential(),
      signingKey,
      defaultOptions,
    );

    const tampered = JSON.parse(JSON.stringify(signedVC)) as Record<string, unknown>;
    (tampered.credentialSubject as Record<string, unknown>).name = "Mallory";

    const ok = await referenceVerify(tampered, signingKey.publicKey);
    expect(ok).toBe(false);
  });
});

describe("prepareJws2020Proof / completeJws2020Proof — two-phase signing", () => {
  it("matches the single-phase output structure", async () => {
    const signingKey = createTestSigningKey(VM);
    const prepared = await prepareJws2020Proof(createTestCredential(), "P-256", defaultOptions);

    expect(prepared.protectedHeaderB64).toBeTruthy();
    expect(prepared.document["@context"]).toContain(JWS_2020_V1_CONTEXT);
    // Signing input starts with ASCII(headerB64 + ".") followed by 64 bytes
    // of verify data (SHA-256 || SHA-256).
    expect(prepared.dataToSign.length).toBe(prepared.protectedHeaderB64.length + 1 + 64);

    const signer = createVerifySigner(signingKey);
    const signatureBytes = await signer(prepared.dataToSign);
    const signedVC = completeJws2020Proof(prepared, signatureBytes);

    expect(signedVC.proof.type).toBe("JsonWebSignature2020");
    const ok = await referenceVerify(
      signedVC as unknown as Record<string, unknown>,
      signingKey.publicKey,
    );
    expect(ok).toBe(true);
  });

  it("rejects an empty signature", async () => {
    const prepared = await prepareJws2020Proof(createTestCredential(), "P-256", defaultOptions);
    expect(() => completeJws2020Proof(prepared, new Uint8Array(0))).toThrow(CryptoError);
  });

  it("requires verificationMethod and proofPurpose", async () => {
    await expect(
      prepareJws2020Proof(createTestCredential(), "P-256", {
        verificationMethod: "",
        proofPurpose: "assertionMethod",
      }),
    ).rejects.toThrow(CryptoError);
    await expect(
      prepareJws2020Proof(createTestCredential(), "P-256", {
        verificationMethod: VM,
        proofPurpose: "",
      }),
    ).rejects.toThrow(CryptoError);
  });

  it("carries domain and challenge into the proof", async () => {
    const signingKey = createTestSigningKey(VM);
    const prepared = await prepareJws2020Proof(createTestCredential(), "P-256", {
      ...defaultOptions,
      domain: "example.com",
      challenge: "nonce-123",
    });
    const signer = createVerifySigner(signingKey);
    const signedVC = completeJws2020Proof(prepared, await signer(prepared.dataToSign));
    expect(signedVC.proof.domain).toBe("example.com");
    expect(signedVC.proof.challenge).toBe("nonce-123");
  });

  it("rejects strict-mode canonicalization of undefined terms", async () => {
    const unsigned = createTestCredential();
    (unsigned.credentialSubject as Record<string, unknown>).notInAnyContext = "x";
    await expect(prepareJws2020Proof(unsigned, "P-256", defaultOptions)).rejects.toThrow();
  });
});

describe("ensureJws2020Context / jws2020ProtectedHeader", () => {
  it("throws when @context is not an array", () => {
    const bad = {
      "@context": "https://www.w3.org/ns/credentials/v2",
    } as unknown as UnsignedCredential;
    expect(() => ensureJws2020Context(bad)).toThrow(CryptoError);
  });

  it("builds the RFC 7797 header without kid or typ", () => {
    expect(jws2020ProtectedHeader("P-256")).toEqual({ alg: "ES256", b64: false, crit: ["b64"] });
    expect(jws2020ProtectedHeader("RSA-2048")).toEqual({
      alg: "PS256",
      b64: false,
      crit: ["b64"],
    });
  });
});

/**
 * Build a Signer-style sign function from a test signing key (mimics what
 * the apps' Signer abstraction does for raw-message signing).
 */
function createVerifySigner(signingKey: SigningKey): (data: Uint8Array) => Promise<Uint8Array> {
  return async (data: Uint8Array) => {
    const s = createSign("SHA256");
    s.update(data);
    return new Uint8Array(s.sign({ key: signingKey.privateKey, dsaEncoding: "ieee-p1363" }));
  };
}
