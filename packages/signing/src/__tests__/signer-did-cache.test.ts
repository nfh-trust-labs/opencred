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
  resetSignerDidDocumentCache,
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
