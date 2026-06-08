import { describe, it, expect } from "vitest";
import {
  didWebVerificationMethodId,
  didWebVerificationMethodIdForIndex,
  keyIndexFromVerificationMethod,
  generateDidWebDocumentMultiKey,
  importDidWebDocument,
} from "../did-web.js";
import type { JWK } from "../types.js";

const DID = "did:web:university.edu";

function jwk(x: string): JWK {
  return { kty: "EC", crv: "P-256", x, y: `${x}-y` } as JWK;
}

describe("didWebVerificationMethodIdForIndex", () => {
  it("builds sequential #key-<n> ids", () => {
    expect(didWebVerificationMethodIdForIndex(DID, 0)).toBe(`${DID}#key-0`);
    expect(didWebVerificationMethodIdForIndex(DID, 3)).toBe(`${DID}#key-3`);
  });

  it("matches the #key-0 convenience helper at index 0", () => {
    expect(didWebVerificationMethodId(DID)).toBe(didWebVerificationMethodIdForIndex(DID, 0));
  });

  it("rejects negative and non-integer indices", () => {
    expect(() => didWebVerificationMethodIdForIndex(DID, -1)).toThrow();
    expect(() => didWebVerificationMethodIdForIndex(DID, 1.5)).toThrow();
  });
});

describe("keyIndexFromVerificationMethod", () => {
  it("parses full ids and bare fragments", () => {
    expect(keyIndexFromVerificationMethod(`${DID}#key-0`)).toBe(0);
    expect(keyIndexFromVerificationMethod(`${DID}#key-12`)).toBe(12);
    expect(keyIndexFromVerificationMethod("#key-4")).toBe(4);
    expect(keyIndexFromVerificationMethod("key-7")).toBe(7);
  });

  it("returns null for non-sequential fragments", () => {
    expect(keyIndexFromVerificationMethod(`${DID}#key-abc`)).toBeNull();
    expect(keyIndexFromVerificationMethod("did:key:z6Mk#z6Mk")).toBeNull();
    expect(keyIndexFromVerificationMethod(`${DID}#0H7thumbprint`)).toBeNull();
  });
});

describe("generateDidWebDocumentMultiKey with revoked keys", () => {
  it("keeps revoked keys in verificationMethod but drops them from every relationship", () => {
    const doc = generateDidWebDocumentMultiKey(DID, [
      { id: `${DID}#key-0`, publicKeyJwk: jwk("k0"), revoked: true },
      { id: `${DID}#key-1`, publicKeyJwk: jwk("k1") },
    ]);

    // Both keys remain resolvable.
    expect(doc.verificationMethod?.map((v) => v.id)).toEqual([`${DID}#key-0`, `${DID}#key-1`]);

    // Only the non-revoked key is referenced by relationships.
    for (const rel of [
      "assertionMethod",
      "authentication",
      "capabilityInvocation",
      "capabilityDelegation",
    ] as const) {
      expect(doc[rel]).toEqual([`${DID}#key-1`]);
    }
  });

  it("lists all keys in relationships when none are revoked", () => {
    const doc = generateDidWebDocumentMultiKey(DID, [
      { id: `${DID}#key-0`, publicKeyJwk: jwk("k0") },
      { id: `${DID}#key-1`, publicKeyJwk: jwk("k1") },
    ]);
    expect(doc.assertionMethod).toEqual([`${DID}#key-0`, `${DID}#key-1`]);
  });

  it("throws when every key is revoked (no usable signing identity)", () => {
    expect(() =>
      generateDidWebDocumentMultiKey(DID, [
        { id: `${DID}#key-0`, publicKeyJwk: jwk("k0"), revoked: true },
      ]),
    ).toThrow(/non-revoked/);
  });

  it("strips private JWK members so no private key leaks into the document", () => {
    const withPrivate = {
      kty: "EC",
      crv: "P-256",
      x: "pub-x",
      y: "pub-y",
      d: "PRIVATE-SCALAR",
    } as unknown as JWK;
    const doc = generateDidWebDocumentMultiKey(DID, [
      { id: `${DID}#key-0`, publicKeyJwk: withPrivate },
    ]);
    const vmJwk = doc.verificationMethod![0]!.publicKeyJwk as Record<string, unknown>;
    expect(vmJwk.d).toBeUndefined();
    expect(vmJwk.x).toBe("pub-x");
    expect(JSON.stringify(doc)).not.toContain("PRIVATE-SCALAR");
  });
});

describe("importDidWebDocument", () => {
  it("extracts keys, indices, max index, and used indices", () => {
    const doc = generateDidWebDocumentMultiKey(DID, [
      { id: `${DID}#key-0`, publicKeyJwk: jwk("k0") },
      { id: `${DID}#key-1`, publicKeyJwk: jwk("k1") },
    ]);

    const imported = importDidWebDocument(doc);
    expect(imported.did).toBe(DID);
    expect(imported.keys.map((k) => k.index)).toEqual([0, 1]);
    expect(imported.maxKeyIndex).toBe(1);
    expect(imported.usedIndices).toEqual([0, 1]);
    expect(imported.keys.every((k) => !k.revoked)).toBe(true);
  });

  it("detects a revoked key (present in verificationMethod, absent from relationships)", () => {
    const doc = generateDidWebDocumentMultiKey(DID, [
      { id: `${DID}#key-0`, publicKeyJwk: jwk("k0"), revoked: true },
      { id: `${DID}#key-1`, publicKeyJwk: jwk("k1") },
    ]);

    const imported = importDidWebDocument(doc);
    const k0 = imported.keys.find((k) => k.index === 0)!;
    const k1 = imported.keys.find((k) => k.index === 1)!;
    expect(k0.revoked).toBe(true);
    expect(k1.revoked).toBe(false);
  });

  it("round-trips: import keys feed straight back into the generator", () => {
    const original = generateDidWebDocumentMultiKey(DID, [
      { id: `${DID}#key-0`, publicKeyJwk: jwk("k0"), revoked: true },
      { id: `${DID}#key-1`, publicKeyJwk: jwk("k1") },
    ]);

    const imported = importDidWebDocument(original);
    const regenerated = generateDidWebDocumentMultiKey(DID, imported.keys);
    expect(regenerated).toEqual(original);
  });

  it("computes the next free index as maxKeyIndex + 1", () => {
    const doc = generateDidWebDocumentMultiKey(DID, [
      { id: `${DID}#key-0`, publicKeyJwk: jwk("k0") },
    ]);
    const imported = importDidWebDocument(doc);
    expect(imported.maxKeyIndex + 1).toBe(1);
  });

  it("rejects non-did:web documents", () => {
    expect(() => importDidWebDocument(null)).toThrow();
    expect(() => importDidWebDocument({ id: "did:key:z6Mk" })).toThrow();
  });

  it("strips private JWK members from an operator-supplied document", () => {
    const malicious = {
      id: DID,
      verificationMethod: [
        {
          id: `${DID}#key-0`,
          type: "JsonWebKey",
          controller: DID,
          publicKeyJwk: { kty: "EC", crv: "P-256", x: "pub-x", y: "pub-y", d: "LEAKED-PRIVATE" },
        },
      ],
      assertionMethod: [`${DID}#key-0`],
    };
    const imported = importDidWebDocument(malicious);
    const k0 = imported.keys[0]!.publicKeyJwk as Record<string, unknown>;
    expect(k0.d).toBeUndefined();
    expect(k0.x).toBe("pub-x");
  });
});
