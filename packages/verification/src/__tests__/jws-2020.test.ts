import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { signCredentialJws2020 } from "@opencred/crypto";
import type { SigningAlgorithm } from "@opencred/crypto";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import type {
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
} from "@opencred/did";
import { verifyJws2020Proof } from "../jws-2020.js";
import { detectFormat, verifyCredential } from "../verifier.js";

const DID = "did:web:university.example";
const VM_ID = `${DID}#key-1`;

function createTestCredential(): UnsignedCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:test-credential-jws2020-verify",
    type: ["VerifiableCredential"],
    issuer: DID,
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder123",
      name: "Jane Doe",
    },
  };
}

function createMockResolver(did: string, verificationMethod: VerificationMethod): DIDResolver {
  return {
    resolve: async (inputDid: string): Promise<DIDResolutionResult> => {
      if (inputDid !== did) {
        return {
          didDocument: null,
          didResolutionMetadata: { error: "notFound" },
          didDocumentMetadata: {},
        };
      }
      return {
        didDocument: {
          "@context": "https://www.w3.org/ns/did/v1",
          id: did,
          verificationMethod: [verificationMethod],
          assertionMethod: [verificationMethod.id],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

async function signWithFreshKey(algorithm: SigningAlgorithm = "P-256"): Promise<{
  signedVC: VerifiableCredential;
  resolver: DIDResolver;
}> {
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

  const signedVC = await signCredentialJws2020(
    createTestCredential(),
    { id: VM_ID, privateKey, publicKey, algorithm },
    { verificationMethod: VM_ID, proofPurpose: "assertionMethod" },
  );
  const resolver = createMockResolver(DID, {
    id: VM_ID,
    type: "JsonWebKey2020",
    controller: DID,
    publicKeyJwk: publicKey.export({ format: "jwk" }) as import("@opencred/did").JWK,
  });
  return { signedVC, resolver };
}

describe("verifyJws2020Proof", () => {
  it.each(["P-256", "P-384", "Ed25519", "RSA-2048"] as const)(
    "verifies a credential signed with %s",
    async (algorithm) => {
      const { signedVC, resolver } = await signWithFreshKey(algorithm);
      const check = await verifyJws2020Proof(signedVC, resolver);
      expect(check).toEqual({ name: "signature", passed: true });
    },
  );

  it("rejects a tampered credential", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const tampered = JSON.parse(JSON.stringify(signedVC)) as VerifiableCredential;
    (tampered.credentialSubject as Record<string, unknown>).name = "Mallory";

    const check = await verifyJws2020Proof(tampered, resolver);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("verification failed");
  });

  it("rejects a tampered proof header", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const tampered = JSON.parse(JSON.stringify(signedVC)) as VerifiableCredential;
    const [, , sig] = (tampered.proof["jws"] as string).split(".");
    const forgedHeader = Buffer.from(
      JSON.stringify({ alg: "ES256", b64: false, crit: ["b64"], extra: "x" }),
    ).toString("base64url");
    tampered.proof["jws"] = `${forgedHeader}..${sig}`;

    const check = await verifyJws2020Proof(tampered, resolver);
    expect(check.passed).toBe(false);
  });

  it("rejects a non-detached (3-segment with payload) jws", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const bad = JSON.parse(JSON.stringify(signedVC)) as VerifiableCredential;
    const [h, , s] = (bad.proof["jws"] as string).split(".");
    bad.proof["jws"] = `${h}.eyJmb28iOiJiYXIifQ.${s}`;

    const check = await verifyJws2020Proof(bad, resolver);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("detached");
  });

  it("rejects a header without b64:false", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const bad = JSON.parse(JSON.stringify(signedVC)) as VerifiableCredential;
    const [, , sig] = (bad.proof["jws"] as string).split(".");
    const header = Buffer.from(JSON.stringify({ alg: "ES256" })).toString("base64url");
    bad.proof["jws"] = `${header}..${sig}`;

    const check = await verifyJws2020Proof(bad, resolver);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("b64");
  });

  it("rejects a disallowed algorithm (alg none)", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const bad = JSON.parse(JSON.stringify(signedVC)) as VerifiableCredential;
    const [, , sig] = (bad.proof["jws"] as string).split(".");
    const header = Buffer.from(JSON.stringify({ alg: "none", b64: false, crit: ["b64"] })).toString(
      "base64url",
    );
    bad.proof["jws"] = `${header}..${sig}`;

    const check = await verifyJws2020Proof(bad, resolver);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("not permitted");
  });

  it("returns a failed check (not a crash) for a header decoding to JSON null", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const bad = JSON.parse(JSON.stringify(signedVC)) as VerifiableCredential;
    const [, , sig] = (bad.proof["jws"] as string).split(".");
    // base64url("null") — JSON.parse succeeds returning null, which must not
    // crash the header property accesses.
    bad.proof["jws"] = `${Buffer.from("null").toString("base64url")}..${sig}`;

    const check = await verifyJws2020Proof(bad, resolver);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("not a JSON object");
  });

  it("rejects a signature segment that is not valid base64url", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const bad = JSON.parse(JSON.stringify(signedVC)) as VerifiableCredential;
    const [h] = (bad.proof["jws"] as string).split(".");
    // '+' and '=' are base64, not base64url — Node decodes them leniently,
    // so the verifier must reject the alphabet explicitly.
    bad.proof["jws"] = `${h}..AB+CD=`;

    const check = await verifyJws2020Proof(bad, resolver);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("not valid base64url");
  });

  it("rejects unknown crit extensions", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const bad = JSON.parse(JSON.stringify(signedVC)) as VerifiableCredential;
    const [, , sig] = (bad.proof["jws"] as string).split(".");
    const header = Buffer.from(
      JSON.stringify({ alg: "ES256", b64: false, crit: ["b64", "exp"] }),
    ).toString("base64url");
    bad.proof["jws"] = `${header}..${sig}`;

    const check = await verifyJws2020Proof(bad, resolver);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("crit");
  });

  it("fails without a resolvable verification method", async () => {
    const { signedVC } = await signWithFreshKey();
    const check = await verifyJws2020Proof(signedVC, undefined);
    expect(check.passed).toBe(false);
    expect(check.detail).toContain("Unable to resolve");
  });
});

describe("detectFormat / verifyCredential — jws-2020 dispatch", () => {
  it("detects an embedded JsonWebSignature2020 proof as jws-2020", async () => {
    const { signedVC } = await signWithFreshKey();
    expect(detectFormat(signedVC as unknown as Record<string, unknown>)).toBe("jws-2020");
  });

  it("keeps envelope precedence: proof.jwt plus a stray jws member is NOT jws-2020", () => {
    const envelope = {
      ...createTestCredential(),
      proof: { type: "JsonWebSignature2020", jwt: "a.b.c", jws: "attacker..controlled" },
    };
    // Must match verifyCredential's envelope-first routing — a stray,
    // never-verified `jws` member must not reroute classification.
    expect(detectFormat(envelope as unknown as Record<string, unknown>)).toBe("data-integrity");
  });

  it("still detects a DataIntegrityProof object as data-integrity", () => {
    const credential = {
      ...createTestCredential(),
      proof: { type: "DataIntegrityProof", proofValue: "z123" },
    };
    expect(detectFormat(credential as unknown as Record<string, unknown>)).toBe("data-integrity");
  });

  it("still routes the vc-jwt envelope (proof.jwt) through the envelope path, not jws-2020", () => {
    const envelope = {
      ...createTestCredential(),
      proof: { type: "JsonWebSignature2020", jwt: "a.b.c" },
    };
    // detectFormat itself sees a proof without `jws` string → data-integrity;
    // verifyCredential short-circuits into the envelope path before that.
    expect(detectFormat(envelope as unknown as Record<string, unknown>)).toBe("data-integrity");
  });

  it("verifyCredential returns VALID for a good jws-2020 credential", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const result = await verifyCredential(signedVC as unknown as Record<string, unknown>, {
      didResolver: resolver,
    });
    expect(result.verified).toBe(true);
    expect(result.code).toBe("VALID");
    expect(result.checks.some((c) => c.name === "signature" && c.passed)).toBe(true);
  });

  it("verifyCredential returns INVALID for a tampered jws-2020 credential", async () => {
    const { signedVC, resolver } = await signWithFreshKey();
    const tampered = JSON.parse(JSON.stringify(signedVC)) as Record<string, unknown>;
    (tampered.credentialSubject as Record<string, unknown>).name = "Mallory";
    const result = await verifyCredential(tampered, { didResolver: resolver });
    expect(result.verified).toBe(false);
    expect(result.code).toBe("INVALID");
  });
});
