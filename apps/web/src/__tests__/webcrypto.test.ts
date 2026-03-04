import { describe, it, expect } from "vitest";
import {
  base64urlEncode,
  base64urlDecode,
  importKeyFile,
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

describe("importKeyFile", () => {
  async function makeTestJwkJson(): Promise<{ json: string; publicKey: CryptoKey }> {
    const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return { json: JSON.stringify(jwk), publicKey: keyPair.publicKey };
  }

  it("imports a JWK file string and returns a non-extractable CryptoKey", async () => {
    const { json } = await makeTestJwkJson();
    const result = await importKeyFile(json);
    expect(result.signingKey.algorithm).toMatchObject({ name: "ECDSA" });
    expect(result.signingKey.extractable).toBe(false);
    expect(result.publicKeyId.length).toBeGreaterThan(0);
  });

  it("rejects invalid JSON", async () => {
    await expect(importKeyFile("{bad}")).rejects.toThrow("Invalid JSON");
  });

  it("rejects unsupported kty", async () => {
    const json = JSON.stringify({ kty: "oct", k: "c2VjcmV0" });
    await expect(importKeyFile(json)).rejects.toThrow('kty must be "EC", "RSA", or "OKP"');
  });

  it("rejects unsupported EC curve", async () => {
    const json = JSON.stringify({ kty: "EC", crv: "P-521", x: "a", y: "b", d: "c" });
    await expect(importKeyFile(json)).rejects.toThrow('crv must be "P-256" or "P-384"');
  });

  it("rejects missing private key component", async () => {
    const json = JSON.stringify({ kty: "EC", crv: "P-256", x: "a", y: "b" });
    await expect(importKeyFile(json)).rejects.toThrow("must contain x, y, and d");
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

  it("imports via importKeyFile and signs data", async () => {
    const { jwk, publicKey } = await generateTestKey();
    const json = JSON.stringify(jwk);
    const result = await importKeyFile(json);

    const data = new TextEncoder().encode("hello world");
    const signature = await signData(result.signingKey, data);
    expect(signature.length).toBe(64);

    // Verify signature with original public key
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

  it("produces a valid signature verifiable with the public key", async () => {
    const { jwk, publicKey } = await generateTestKey();
    const json = JSON.stringify(jwk);
    const { signingKey } = await importKeyFile(json);
    const data = new TextEncoder().encode("hello world");

    const signature = await signData(signingKey, data);

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

  it("extractPublicKeyId produces a stable identifier without d field", async () => {
    const { jwk } = await generateTestKey();
    // extractPublicKeyId should work with just x and y — no d required
    const id1 = extractPublicKeyId({ x: jwk.x, y: jwk.y });
    const id2 = extractPublicKeyId({ x: jwk.x, y: jwk.y });
    expect(id1).toBe(id2);
    expect(id1.length).toBeGreaterThan(0);
    // Should be base64url-safe
    expect(id1).not.toContain("+");
    expect(id1).not.toContain("/");
    expect(id1).not.toContain("=");
  });

  it("importKeyFile publicKeyId matches extractPublicKeyId", async () => {
    const { jwk } = await generateTestKey();
    const json = JSON.stringify(jwk);
    const { publicKeyId } = await importKeyFile(json);
    const extractedId = extractPublicKeyId({ x: jwk.x, y: jwk.y });
    expect(publicKeyId).toBe(extractedId);
  });
});
