import { describe, it, expect } from "vitest";
import {
  base64urlEncode,
  base64urlDecode,
  parseJwk,
  importPrivateKey,
  signData,
  extractPublicKeyId,
} from "../crypto/webcrypto";

describe("base64url", () => {
  it("round-trips encode/decode", () => {
    const original = new Uint8Array([0, 1, 2, 255, 128, 64]);
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(original);
  });

  it("produces URL-safe characters", () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) bytes[i] = i;
    const encoded = base64urlEncode(bytes);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
  });
});

describe("parseJwk", () => {
  const validJwk = JSON.stringify({
    kty: "EC",
    crv: "P-256",
    x: "abc",
    y: "def",
    d: "ghi",
  });

  it("parses a valid EC P-256 JWK", () => {
    const jwk = parseJwk(validJwk);
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    expect(jwk.d).toBe("ghi");
  });

  it("rejects invalid JSON", () => {
    expect(() => parseJwk("{bad}")).toThrow("Invalid JSON");
  });

  it("rejects non-EC kty", () => {
    expect(() =>
      parseJwk(JSON.stringify({ kty: "RSA", crv: "P-256", x: "a", y: "b", d: "c" })),
    ).toThrow('kty must be "EC"');
  });

  it("rejects non-P-256 curve", () => {
    expect(() =>
      parseJwk(JSON.stringify({ kty: "EC", crv: "P-384", x: "a", y: "b", d: "c" })),
    ).toThrow('crv must be "P-256"');
  });

  it("rejects missing private key component", () => {
    expect(() => parseJwk(JSON.stringify({ kty: "EC", crv: "P-256", x: "a", y: "b" }))).toThrow(
      "must contain x, y, and d",
    );
  });
});

describe("WebCrypto integration", () => {
  // Generate a real P-256 key pair for testing
  async function generateTestKey() {
    const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return {
      jwk: { kty: "EC" as const, crv: "P-256" as const, x: jwk.x!, y: jwk.y!, d: jwk.d! },
      publicKey: keyPair.publicKey,
    };
  }

  it("imports a key and signs data", async () => {
    const { jwk } = await generateTestKey();
    const key = await importPrivateKey(jwk);
    expect(key.algorithm).toMatchObject({ name: "ECDSA" });
    expect(key.extractable).toBe(false);

    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const signature = await signData(key, data);
    // P-256 ECDSA signature is 64 bytes (r || s)
    expect(signature.length).toBe(64);
  });

  it("produces a valid signature verifiable with the public key", async () => {
    const { jwk, publicKey } = await generateTestKey();
    const data = new TextEncoder().encode("hello world");

    const key = await importPrivateKey(jwk);
    const signature = await signData(key, data);

    // Copy to plain ArrayBuffer for TypeScript's BufferSource constraint
    const sigBuf = new ArrayBuffer(signature.byteLength);
    new Uint8Array(sigBuf).set(signature);
    const dataBuf = new ArrayBuffer(data.byteLength);
    new Uint8Array(dataBuf).set(data);
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      sigBuf,
      dataBuf,
    );
    expect(valid).toBe(true);
  });

  it("extractPublicKeyId produces a stable identifier", async () => {
    const { jwk } = await generateTestKey();
    const id1 = extractPublicKeyId(jwk);
    const id2 = extractPublicKeyId(jwk);
    expect(id1).toBe(id2);
    expect(id1.length).toBeGreaterThan(0);
    // Should be base64url-safe
    expect(id1).not.toContain("+");
    expect(id1).not.toContain("/");
    expect(id1).not.toContain("=");
  });
});
