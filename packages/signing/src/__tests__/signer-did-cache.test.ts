/**
 * Tests for the in-process signer DID document cache (#571 — scale Tier 1 #3).
 *
 * The cache is keyed on `signer.metadata.fingerprint` (SHA-256 of the SPKI-
 * encoded public key). These tests cover:
 *
 *   - cache miss → resolver invoked → entry stored
 *   - cache hit  → same reference returned, resolver NOT invoked again
 *   - distinct signers (distinct fingerprints) → independent entries
 *   - identical fingerprints from two Signer objects → shared entry
 *   - did:web (unsupported) → throws and does NOT cache
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { buildSigner } from "../software-signer.js";
import {
  getCachedSignerDidDocument,
  signerDidDocumentCacheSize,
  signerDidDocumentCacheMaxSize,
  resetSignerDidDocumentCache,
  resolveSignerDidCacheMaxSize,
} from "../signer-did-cache.js";
import * as didKeyModule from "@opencred/did";

function generateEcSigner() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return buildSigner(privateKey, publicKey);
}

function generateEd25519Signer() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return buildSigner(privateKey, publicKey);
}

function generateRsaSigner() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return buildSigner(privateKey, publicKey);
}

beforeEach(() => {
  resetSignerDidDocumentCache();
});

describe("getCachedSignerDidDocument", () => {
  it("returns a DID document for a did:key signer (P-256)", async () => {
    const signer = generateEcSigner();
    expect(signer.id.startsWith("did:key:")).toBe(true);

    const doc = await getCachedSignerDidDocument(signer);
    expect(doc.id).toBe(signer.id.split("#")[0]);
    expect(doc.verificationMethod?.length).toBe(1);
    expect(doc.verificationMethod?.[0].id).toBe(signer.id);
    expect(doc.assertionMethod).toContain(signer.id);
  });

  it("returns a DID document for a did:key signer (Ed25519)", async () => {
    const signer = generateEd25519Signer();
    expect(signer.id.startsWith("did:key:")).toBe(true);
    const doc = await getCachedSignerDidDocument(signer);
    expect(doc.id).toBe(signer.id.split("#")[0]);
  });

  it("returns a DID document for a did:jwk signer (RSA)", async () => {
    const signer = generateRsaSigner();
    expect(signer.id.startsWith("did:jwk:")).toBe(true);

    const doc = await getCachedSignerDidDocument(signer);
    expect(doc.id).toBe(signer.id.split("#")[0]);
    expect(doc.verificationMethod?.length).toBe(1);
    // did:jwk fragments are always "#0"
    expect(doc.verificationMethod?.[0].id).toBe(`${doc.id}#0`);
  });

  it("returns the SAME reference on a cache hit (memoization)", async () => {
    const signer = generateEcSigner();

    const first = await getCachedSignerDidDocument(signer);
    const second = await getCachedSignerDidDocument(signer);

    // Identity equality, not just structural equality — proves we did not
    // re-allocate or re-resolve on the second call.
    expect(second).toBe(first);
    expect(signerDidDocumentCacheSize()).toBe(1);
  });

  it("does NOT invoke the resolver on a cache hit", async () => {
    const signer = generateEcSigner();
    const resolveSpy = vi.spyOn(didKeyModule.DIDKeyResolver.prototype, "resolve");

    // First call — miss, resolver should be invoked exactly once.
    await getCachedSignerDidDocument(signer);
    expect(resolveSpy).toHaveBeenCalledTimes(1);

    // Subsequent calls — hits, the spy count must NOT increase.
    await getCachedSignerDidDocument(signer);
    await getCachedSignerDidDocument(signer);
    await getCachedSignerDidDocument(signer);
    expect(resolveSpy).toHaveBeenCalledTimes(1);

    resolveSpy.mockRestore();
  });

  it("stores independent entries for signers with different fingerprints", async () => {
    const a = generateEcSigner();
    const b = generateEcSigner();
    expect(a.metadata.fingerprint).not.toBe(b.metadata.fingerprint);

    const docA = await getCachedSignerDidDocument(a);
    const docB = await getCachedSignerDidDocument(b);

    expect(docA).not.toBe(docB);
    expect(docA.id).not.toBe(docB.id);
    expect(signerDidDocumentCacheSize()).toBe(2);
  });

  it("shares an entry across two Signer objects with the same fingerprint", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

    const signerOne = buildSigner(privateKey, publicKey, "label-one");
    const signerTwo = buildSigner(privateKey, publicKey, "label-two");

    // Two distinct Signer wrappers, but the underlying public key (and
    // therefore the fingerprint cache key) is identical.
    expect(signerOne.metadata.fingerprint).toBe(signerTwo.metadata.fingerprint);

    const docOne = await getCachedSignerDidDocument(signerOne);
    const docTwo = await getCachedSignerDidDocument(signerTwo);

    expect(docTwo).toBe(docOne);
    expect(signerDidDocumentCacheSize()).toBe(1);
  });

  it("evicts the least-recently-used entry when the cap is reached", async () => {
    // Bring the cap down to a value we can drive without churning hundreds
    // of EC keypairs in the test process. The exact number isn't important
    // — what matters is that we cross it by exactly one insertion and
    // observe the first-inserted entry get evicted.
    const previousCap = process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
    process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = "4";
    resetSignerDidDocumentCache();
    try {
      expect(signerDidDocumentCacheMaxSize()).toBe(4);

      const signers = Array.from({ length: 5 }, () => generateEcSigner());

      // Insert four entries — exactly at the cap.
      for (let i = 0; i < 4; i++) {
        await getCachedSignerDidDocument(signers[i]);
      }
      expect(signerDidDocumentCacheSize()).toBe(4);

      // Cross the cap with a fifth insertion. The first-inserted entry
      // (signers[0]) is now the LRU and must be evicted.
      await getCachedSignerDidDocument(signers[4]);
      expect(signerDidDocumentCacheSize()).toBe(4);

      // Verify the eviction: re-fetching signers[0] must hit the
      // resolver again because the entry was dropped.
      const resolveSpy = vi.spyOn(didKeyModule.DIDKeyResolver.prototype, "resolve");
      await getCachedSignerDidDocument(signers[0]);
      expect(resolveSpy).toHaveBeenCalledTimes(1);
      resolveSpy.mockRestore();
    } finally {
      if (previousCap === undefined) {
        delete process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
      } else {
        process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = previousCap;
      }
      resetSignerDidDocumentCache();
    }
  });

  it("moves an entry to MRU on hit (touched entries are not evicted)", async () => {
    const previousCap = process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
    process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = "3";
    resetSignerDidDocumentCache();
    try {
      const a = generateEcSigner();
      const b = generateEcSigner();
      const c = generateEcSigner();
      const d = generateEcSigner();

      await getCachedSignerDidDocument(a);
      await getCachedSignerDidDocument(b);
      await getCachedSignerDidDocument(c);

      // Touch `a`, making it MRU. `b` is now the LRU.
      await getCachedSignerDidDocument(a);

      // Insert `d` — should evict `b`, NOT `a`.
      await getCachedSignerDidDocument(d);
      expect(signerDidDocumentCacheSize()).toBe(3);

      // Confirm `a` is still cached (resolver not called), but `b` is gone.
      const resolveSpy = vi.spyOn(didKeyModule.DIDKeyResolver.prototype, "resolve");
      await getCachedSignerDidDocument(a);
      expect(resolveSpy).toHaveBeenCalledTimes(0); // a is still cached
      await getCachedSignerDidDocument(b);
      expect(resolveSpy).toHaveBeenCalledTimes(1); // b was evicted, re-resolved
      resolveSpy.mockRestore();
    } finally {
      if (previousCap === undefined) {
        delete process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
      } else {
        process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = previousCap;
      }
      resetSignerDidDocumentCache();
    }
  });

  it("uses the default cap of 256 when OPENCRED_SIGNER_DID_CACHE_SIZE is unset", () => {
    const previous = process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
    delete process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
    try {
      expect(resolveSignerDidCacheMaxSize()).toBe(256);
    } finally {
      if (previous !== undefined) {
        process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = previous;
      }
    }
  });

  it("falls back to the default when the env var is non-numeric or non-positive", () => {
    const previous = process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
    try {
      process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = "not-a-number";
      expect(resolveSignerDidCacheMaxSize()).toBe(256);

      process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = "0";
      expect(resolveSignerDidCacheMaxSize()).toBe(256);

      process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = "-1";
      expect(resolveSignerDidCacheMaxSize()).toBe(256);
    } finally {
      if (previous === undefined) {
        delete process.env.OPENCRED_SIGNER_DID_CACHE_SIZE;
      } else {
        process.env.OPENCRED_SIGNER_DID_CACHE_SIZE = previous;
      }
    }
  });

  it("inserts 257 entries with the default cap and evicts the oldest", async () => {
    // Acceptance criterion: insert 257 entries, assert oldest evicted.
    // 257 EC keypairs is a lot for a unit test (~1 s on a modern laptop),
    // but it's the explicit ask in issue #573 to confirm the default cap
    // of 256 is real. If this test gets slow on CI we can shrink and
    // move the 257 assertion into a perf suite — for now, keep it
    // honest.
    resetSignerDidDocumentCache();
    expect(signerDidDocumentCacheMaxSize()).toBe(256);

    const signers = Array.from({ length: 257 }, () => generateEcSigner());
    for (const s of signers) {
      await getCachedSignerDidDocument(s);
    }

    expect(signerDidDocumentCacheSize()).toBe(256);

    // The oldest (signers[0]) must have been evicted — re-fetching
    // triggers the resolver again.
    const resolveSpy = vi.spyOn(didKeyModule.DIDKeyResolver.prototype, "resolve");
    await getCachedSignerDidDocument(signers[0]);
    expect(resolveSpy).toHaveBeenCalledTimes(1);
    resolveSpy.mockRestore();
  });

  it("throws for an unsupported DID method and does NOT cache the failure", async () => {
    // Construct a signer-like object pointing at a did:web identifier — this
    // exercises the "DID method not synthesisable offline" branch. We don't
    // build an actual did:web Signer (there is no software signer for it),
    // we just type-cast to satisfy the parameter shape.
    const did = "did:web:example.com";
    const fakeSigner = {
      id: `${did}#key-1`,
      algorithm: "P-256",
      type: "software",
      metadata: {
        id: `${did}#key-1`,
        algorithm: "P-256",
        type: "software",
        fingerprint: "deadbeef-cafe",
      },
      sign: async () => new Uint8Array(),
    } as unknown as Parameters<typeof getCachedSignerDidDocument>[0];

    await expect(getCachedSignerDidDocument(fakeSigner)).rejects.toThrow(
      /only did:key and did:jwk are supported/,
    );
    expect(signerDidDocumentCacheSize()).toBe(0);
  });
});
