/**
 * Tests for the precomputed proof config helpers
 * ({@link precomputeProofConfig} + {@link prepareProofWithPrecomputedConfig}).
 *
 * Verifies that the optimized batch-signing path produces signatures that
 * are bit-identical to the non-optimized {@link prepareProof} path when
 * `created` is held constant, and that the precomputed proof-config hash
 * is reused across rows (i.e. the per-row work skips the proof-config
 * canonicalize-and-hash step).
 *
 * #571 — scale Tier 1 #4.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign } from "node:crypto";
import type { UnsignedCredential } from "@opencred/vc-core";
import {
  prepareProof,
  precomputeProofConfig,
  prepareProofWithPrecomputedConfig,
  completeProof,
  verifyProof,
  canonicalize,
} from "../data-integrity.js";
import type { ProofOptions } from "../types.js";

const proofOptions: ProofOptions = {
  verificationMethod: "did:example:issuer#key-1",
  proofPurpose: "assertionMethod",
};

function makeUnsigned(name: string): UnsignedCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: `urn:uuid:test-${name}`,
    type: ["VerifiableCredential"],
    issuer: "did:example:issuer",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: `did:example:holder-${name}`,
      name,
    },
  };
}

describe("precomputeProofConfig", () => {
  it("returns a bundle with proof config, hash, and hash algorithm (P-256)", async () => {
    const bundle = await precomputeProofConfig(makeUnsigned("alice"), proofOptions, "P-256");
    expect(bundle.proofConfig.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(bundle.proofConfig.verificationMethod).toBe(proofOptions.verificationMethod);
    expect(bundle.hashAlgorithm).toBe("sha256");
    // SHA-256 → 32-byte digest
    expect(bundle.proofConfigHash.length).toBe(32);
  });

  it("uses sha384 for P-384", async () => {
    const bundle = await precomputeProofConfig(makeUnsigned("a"), proofOptions, "P-384");
    expect(bundle.hashAlgorithm).toBe("sha384");
    expect(bundle.proofConfigHash.length).toBe(48);
  });

  it("uses eddsa-rdfc-2022 cryptosuite + sha256 for Ed25519", async () => {
    const bundle = await precomputeProofConfig(makeUnsigned("a"), proofOptions, "Ed25519");
    expect(bundle.proofConfig.cryptosuite).toBe("eddsa-rdfc-2022");
    expect(bundle.hashAlgorithm).toBe("sha256");
    expect(bundle.proofConfigHash.length).toBe(32);
  });

  it("throws for RSA — data-integrity is EC/Ed25519 only", async () => {
    await expect(
      precomputeProofConfig(makeUnsigned("a"), proofOptions, "RSA-2048"),
    ).rejects.toThrow(/RSA-2048/);
  });

  it("requires verificationMethod and proofPurpose", async () => {
    await expect(
      precomputeProofConfig(makeUnsigned("a"), { verificationMethod: "", proofPurpose: "x" }),
    ).rejects.toThrow(/verificationMethod/);
    await expect(
      precomputeProofConfig(makeUnsigned("a"), { verificationMethod: "x", proofPurpose: "" }),
    ).rejects.toThrow(/proofPurpose/);
  });
});

describe("prepareProofWithPrecomputedConfig", () => {
  it("produces a 64-byte signing input (proofConfigHash || docHash) for P-256", async () => {
    const bundle = await precomputeProofConfig(makeUnsigned("a"), proofOptions, "P-256");
    const { dataToSign } = await prepareProofWithPrecomputedConfig(makeUnsigned("a"), bundle);
    expect(dataToSign.length).toBe(64);
    // First 32 bytes match the precomputed proof config hash
    expect(Array.from(dataToSign.slice(0, 32))).toEqual(Array.from(bundle.proofConfigHash));
  });

  it("reuses the SAME proofConfig reference across calls (no re-allocation)", async () => {
    const bundle = await precomputeProofConfig(makeUnsigned("a"), proofOptions, "P-256");
    const { proofConfig: pcOne } = await prepareProofWithPrecomputedConfig(
      makeUnsigned("a"),
      bundle,
    );
    const { proofConfig: pcTwo } = await prepareProofWithPrecomputedConfig(
      makeUnsigned("b"),
      bundle,
    );
    expect(pcTwo).toBe(pcOne);
    expect(pcOne).toBe(bundle.proofConfig);
  });

  it("matches prepareProof byte-for-byte when `created` is held constant", async () => {
    // Build a reference proof config + signing input via the non-optimized
    // path. Then verify the optimized path produces identical bytes for the
    // same `created` timestamp.
    const reference = await prepareProof(makeUnsigned("alice"), proofOptions, "P-256");

    // Inject reference.proofConfig.created into the precomputed bundle so
    // both paths are comparing apples to apples — `precomputeProofConfig`
    // would otherwise capture a fresh `new Date()` and the proof-config
    // canonical forms would differ.
    const bundle = await precomputeProofConfig(makeUnsigned("alice"), proofOptions, "P-256");
    bundle.proofConfig.created = reference.proofConfig.created;
    // Recompute the hash to match.
    const { sha256 } = await import("../hash.js");
    const canonical = await canonicalize(bundle.proofConfig as unknown as Record<string, unknown>);
    bundle.proofConfigHash = sha256(canonical);

    const optimized = await prepareProofWithPrecomputedConfig(makeUnsigned("alice"), bundle);

    expect(Array.from(optimized.dataToSign)).toEqual(Array.from(reference.dataToSign));
  });

  it("reuses the same proof-config hash across rows — no per-row recomputation", async () => {
    // We can't spy on the internal `canonicalize` call (the helpers use a
    // module-local reference, not the namespace export), but we can
    // observe the optimization directly: every row that comes out of
    // `prepareProofWithPrecomputedConfig` MUST have the same first 32
    // bytes in `dataToSign` as the precomputed bundle's `proofConfigHash`.
    // If we forgot to hoist (or accidentally rebuilt the proof config per
    // row), `created` would drift and the leading 32 bytes would change.
    const bundle = await precomputeProofConfig(makeUnsigned("template"), proofOptions, "P-256");
    const sharedHash = Array.from(bundle.proofConfigHash);

    for (let i = 0; i < 5; i++) {
      const { dataToSign } = await prepareProofWithPrecomputedConfig(
        makeUnsigned(`row-${i}`),
        bundle,
      );
      expect(Array.from(dataToSign.slice(0, 32))).toEqual(sharedHash);
    }
  });

  it("yields verifiable credentials when signed and stitched", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const bundle = await precomputeProofConfig(makeUnsigned("alice"), proofOptions, "P-256");

    const unsigned = makeUnsigned("alice");
    const { dataToSign, proofConfig } = await prepareProofWithPrecomputedConfig(unsigned, bundle);

    const signer = createSign("SHA256");
    signer.update(dataToSign);
    const sig = new Uint8Array(signer.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }));

    const signed = completeProof(unsigned, proofConfig, sig);
    const result = await verifyProof(signed, { publicKey });
    expect(result.verified).toBe(true);
  });
});
