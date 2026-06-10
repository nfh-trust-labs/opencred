/**
 * Tests for the public @opencred/verify SDK facade.
 *
 * The verification engine itself is exhaustively tested in
 * `@opencred/verification` — these tests pin the SDK's public contract:
 * the factory wiring, the offline zero-config path, the one-shot helpers,
 * and the "structured result, never an unhandled throw" guarantee for
 * hostile or malformed input.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import * as jose from "jose";
import { encodeDidJwk, type JWK, type DIDResolver } from "@opencred/did";
import { createVerifier, verifyCredential, verifyPdf, detectFormat } from "../index.js";

function generateTestKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

async function createVcJwt(
  privateKey: KeyObject,
  payload: Record<string, unknown>,
): Promise<string> {
  const key = await jose.importPKCS8(
    privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    "ES256",
  );
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", typ: "JWT" })
    .setIssuedAt()
    .sign(key);
}

/** A valid VC-JWT signed by a did:jwk issuer — verifiable fully offline. */
async function createOfflineCredential(extraVcFields: Record<string, unknown> = {}): Promise<{
  jwt: string;
  issuerDid: string;
}> {
  const { privateKey, publicKey } = generateTestKeyPair();
  const issuerDid = encodeDidJwk(publicKey.export({ format: "jwk" }) as JWK);
  const jwt = await createVcJwt(privateKey, {
    iss: issuerDid,
    nbf: Math.floor(Date.now() / 1000) - 60,
    vc: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential"],
      credentialSubject: { name: "Jane Doe" },
      ...extraVcFields,
    },
  });
  return { jwt, issuerDid };
}

describe("createVerifier — zero-config offline path", () => {
  it("verifies a did:jwk VC-JWT with no configuration at all", async () => {
    const { jwt } = await createOfflineCredential();
    const verify = createVerifier();

    const result = await verify(jwt);

    expect(result.verified).toBe(true);
    expect(result.code).toBe("VALID");
    expect(result.checks.some((c) => c.name === "signature" && c.passed)).toBe(true);
  });

  it("rejects a tampered VC-JWT", async () => {
    const { jwt } = await createOfflineCredential();
    const [header, payload, sig] = jwt.split(".");
    const tamperedPayload = JSON.parse(Buffer.from(payload!, "base64url").toString()) as Record<
      string,
      unknown
    >;
    (tamperedPayload.vc as Record<string, unknown>).credentialSubject = { name: "Mallory" };
    const tampered = [
      header,
      Buffer.from(JSON.stringify(tamperedPayload)).toString("base64url"),
      sig,
    ].join(".");

    const result = await createVerifier()(tampered);

    expect(result.verified).toBe(false);
  });

  it("is reusable across multiple verifications", async () => {
    const verify = createVerifier();
    const [a, b] = await Promise.all([createOfflineCredential(), createOfflineCredential()]);

    const [ra, rb] = await Promise.all([verify(a.jwt), verify(b.jwt)]);

    expect(ra.verified).toBe(true);
    expect(rb.verified).toBe(true);
  });
});

describe("createVerifier — malformed input never throws", () => {
  const verify = createVerifier();

  it("returns a structured failure for a garbage string", async () => {
    const result = await verify("not-a-credential-at-all");
    expect(result.verified).toBe(false);
    expect(typeof result.code).toBe("string");
    expect(Array.isArray(result.checks)).toBe(true);
  });

  it("returns a structured failure for an empty string", async () => {
    const result = await verify("");
    expect(result.verified).toBe(false);
  });

  it("returns a structured failure for a truncated JWT", async () => {
    const { jwt } = await createOfflineCredential();
    const result = await verify(jwt.slice(0, Math.floor(jwt.length / 2)));
    expect(result.verified).toBe(false);
  });

  it("returns a structured failure for a JWT with non-JSON payload", async () => {
    const bogus = `${Buffer.from('{"alg":"ES256"}').toString("base64url")}.${Buffer.from(
      "definitely not json",
    ).toString("base64url")}.AAAA`;
    const result = await verify(bogus);
    expect(result.verified).toBe(false);
  });

  it("returns a structured failure for an oversized (>1 MiB) token", async () => {
    const huge = "eyJ" + "A".repeat(1_100_000);
    const result = await verify(huge);
    expect(result.verified).toBe(false);
  });
});

describe("createVerifier — .pdf", () => {
  it("returns a structured failure for non-PDF bytes", async () => {
    const result = await createVerifier().pdf(new Uint8Array([1, 2, 3, 4]));
    expect(result.verified).toBe(false);
    expect(Array.isArray(result.checks)).toBe(true);
  });

  it("returns a structured failure for an empty byte array", async () => {
    const result = await createVerifier().pdf(new Uint8Array(0));
    expect(result.verified).toBe(false);
  });
});

describe("createVerifier — custom didResolver", () => {
  it("surfaces a throwing resolver as a structured failure, not an exception", async () => {
    const explodingResolver: DIDResolver = {
      resolve: async () => {
        throw new Error("resolver exploded");
      },
    };
    const { jwt } = await createOfflineCredential();

    const result = await createVerifier({ didResolver: explodingResolver })(jwt);

    expect(result.verified).toBe(false);
  });

  it("surfaces an unresolvable issuer as a structured failure", async () => {
    const notFoundResolver: DIDResolver = {
      resolve: async () => ({
        didDocument: null,
        didResolutionMetadata: { error: "notFound" },
        didDocumentMetadata: {},
      }),
    };
    const { jwt } = await createOfflineCredential();

    const result = await createVerifier({ didResolver: notFoundResolver })(jwt);

    expect(result.verified).toBe(false);
  });
});

describe("revocation visibility without DeDi", () => {
  it("adds a 'revocation NOT checked' row when the credential declares credentialStatus", async () => {
    const { jwt } = await createOfflineCredential({
      credentialStatus: {
        id: "https://dedi.example.com/dedi/lookup/example.com/vc-revocation-registry/abc",
        type: "RevocationList2020Status",
      },
    });

    const result = await createVerifier()(jwt);

    expect(result.verified).toBe(true);
    const row = result.checks.find((c) => c.name === "revocation");
    expect(row).toBeDefined();
    expect(row!.passed).toBe(true);
    expect(row!.detail).toMatch(/NOT checked/);
  });
});

describe("one-shot helpers and re-exports", () => {
  it("verifyCredential() verifies without an explicit verifier instance", async () => {
    const { jwt } = await createOfflineCredential();
    const result = await verifyCredential(jwt);
    expect(result.verified).toBe(true);
  });

  it("verifyPdf() returns a structured failure for non-PDF bytes", async () => {
    const result = await verifyPdf(new Uint8Array([0x25, 0x50])); // truncated "%P"
    expect(result.verified).toBe(false);
  });

  it("detectFormat() classifies a VC-JWT compact string", async () => {
    const { jwt } = await createOfflineCredential();
    expect(detectFormat(jwt)).toBe("vc-jwt");
  });
});
