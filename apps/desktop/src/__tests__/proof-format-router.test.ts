/**
 * Tests for the proof format router.
 *
 * Validates that signWithFormat correctly routes to vc-jwt, data-integrity,
 * and sd-jwt-vc signing paths, and rejects unsupported algorithm/format combos.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { createSoftwareSigner } from "../signing/software-signer";
import { signWithFormat } from "../signing/proof-format-router";
import { CredentialBuilder } from "@opencred/vc-core";
import { CryptoError } from "@opencred/shared";
import type { Signer } from "../signing/types";

let tmpDir: string;
let pemKeyPath: string;

// Generate a P-256 key pair for testing
const { privateKey: testPrivateKey } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
});

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-pfr-test-"));

  const pemKey = testPrivateKey.export({ format: "pem", type: "pkcs8" }) as string;
  pemKeyPath = path.join(tmpDir, "test-key.pem");
  fs.writeFileSync(pemKeyPath, pemKey);
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function buildUnsignedCredential() {
  return new CredentialBuilder()
    .setIssuer("did:web:test.example")
    .setValidFrom("2025-01-01T00:00:00Z")
    .setCredentialSubject({ name: "Test" })
    .build();
}

describe("signWithFormat", () => {
  it("vc-jwt produces isCompactToken false with JsonWebSignature2020", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);
    const unsigned = buildUnsignedCredential();

    const result = await signWithFormat(signer, unsigned, "vc-jwt", {
      verificationMethod: signer.id,
    });

    expect(result.isCompactToken).toBe(false);
    const parsed = JSON.parse(result.signedOutput);
    expect(parsed.proof.type).toBe("JsonWebSignature2020");
  });

  it("data-integrity with ECDSA produces isCompactToken false with DataIntegrityProof", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);
    const unsigned = buildUnsignedCredential();

    const result = await signWithFormat(signer, unsigned, "data-integrity", {
      verificationMethod: signer.id,
    });

    expect(result.isCompactToken).toBe(false);
    const parsed = JSON.parse(result.signedOutput);
    expect(parsed.proof.type).toBe("DataIntegrityProof");
  });

  it("jws-2020 produces a detached JsonWebSignature2020 embedded proof", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);
    const unsigned = buildUnsignedCredential();

    const result = await signWithFormat(signer, unsigned, "jws-2020", {
      verificationMethod: signer.id,
    });

    expect(result.isCompactToken).toBe(false);
    const parsed = JSON.parse(result.signedOutput);
    expect(parsed.proof.type).toBe("JsonWebSignature2020");
    expect(parsed.proof.jwt).toBeUndefined();
    expect(parsed.proof.proofPurpose).toBe("assertionMethod");
    expect(parsed.proof.verificationMethod).toBe(signer.id);
    expect(parsed["@context"]).toContain("https://w3id.org/security/suites/jws-2020/v1");

    const jwsParts = (parsed.proof.jws as string).split(".");
    expect(jwsParts).toHaveLength(3);
    expect(jwsParts[1]).toBe(""); // detached payload
    const header = JSON.parse(Buffer.from(jwsParts[0], "base64url").toString());
    expect(header).toEqual({ alg: "ES256", b64: false, crit: ["b64"] });
  });

  it("data-integrity with RSA throws CryptoError", async () => {
    const rsaSigner: Signer = {
      id: "did:web:test.example#key-rsa",
      algorithm: "RSA-2048",
      type: "software",
      metadata: {
        id: "did:web:test.example#key-rsa",
        algorithm: "RSA-2048",
        type: "software",
        fingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
      },
      sign: async (_data: Uint8Array) => new Uint8Array(256),
    };

    const unsigned = buildUnsignedCredential();

    await expect(
      signWithFormat(rsaSigner, unsigned, "data-integrity", {
        verificationMethod: rsaSigner.id,
      }),
    ).rejects.toThrow(CryptoError);
  });

  it("sd-jwt-vc produces isCompactToken true with ~ separators", async () => {
    const { signer } = createSoftwareSigner(pemKeyPath);
    const unsigned = buildUnsignedCredential();

    const result = await signWithFormat(signer, unsigned, "sd-jwt-vc", {
      verificationMethod: signer.id,
      selectiveDisclosureClaims: ["name"],
    });

    expect(result.isCompactToken).toBe(true);
    expect(result.signedOutput).toContain("~");
  });
});
