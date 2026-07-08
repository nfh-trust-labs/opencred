import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign, createVerify, sign, verify } from "node:crypto";
import { multibaseEncode } from "@opencred/crypto";
import { publicKeyFromMultibase } from "../key-utils.js";

describe("publicKeyFromMultibase", () => {
  it("should convert a multibase-encoded P-256 key to a KeyObject", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });

    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
    const compressedPoint = Buffer.alloc(33);
    compressedPoint[0] = prefix;
    x.copy(compressedPoint, 1);

    const multicodec = Buffer.alloc(2 + 33);
    multicodec[0] = 0x80;
    multicodec[1] = 0x24;
    compressedPoint.copy(multicodec, 2);

    const multibaseKey = multibaseEncode(multicodec);
    const result = publicKeyFromMultibase(multibaseKey);

    expect(result).not.toBeNull();
    expect(result!.type).toBe("public");
    expect(result!.asymmetricKeyType).toBe("ec");
  });

  it("should produce a key that can verify signatures", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });

    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
    const compressedPoint = Buffer.alloc(33);
    compressedPoint[0] = prefix;
    x.copy(compressedPoint, 1);
    const multicodec = Buffer.alloc(2 + 33);
    multicodec[0] = 0x80;
    multicodec[1] = 0x24;
    compressedPoint.copy(multicodec, 2);
    const multibaseKey = multibaseEncode(multicodec);

    const signer = createSign("SHA256");
    signer.update("test data");
    const signature = signer.sign(privateKey);

    const reconstructedKey = publicKeyFromMultibase(multibaseKey)!;
    const verifier = createVerify("SHA256");
    verifier.update("test data");
    expect(verifier.verify(reconstructedKey, signature)).toBe(true);
  });

  it("should convert a multibase-encoded Ed25519 key to a KeyObject", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" });
    const rawKey = Buffer.from(jwk.x!, "base64url");

    const multicodec = Buffer.alloc(2 + 32);
    multicodec[0] = 0xed;
    multicodec[1] = 0x01;
    rawKey.copy(multicodec, 2);

    const multibaseKey = multibaseEncode(multicodec);
    const result = publicKeyFromMultibase(multibaseKey);

    expect(result).not.toBeNull();
    expect(result!.type).toBe("public");
    expect(result!.asymmetricKeyType).toBe("ed25519");
  });

  it("should produce an Ed25519 key that can verify signatures", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" });
    const rawKey = Buffer.from(jwk.x!, "base64url");

    const multicodec = Buffer.alloc(2 + 32);
    multicodec[0] = 0xed;
    multicodec[1] = 0x01;
    rawKey.copy(multicodec, 2);

    const multibaseKey = multibaseEncode(multicodec);

    const testData = Buffer.from("test data for ed25519");
    const signature = sign(null, testData, privateKey);

    const reconstructedKey = publicKeyFromMultibase(multibaseKey)!;
    expect(verify(null, testData, reconstructedKey, signature)).toBe(true);
  });

  it("should return null for unknown multicodec prefix", () => {
    const bytes = new Uint8Array(35);
    bytes[0] = 0xaa;
    bytes[1] = 0xbb;
    const multibaseKey = multibaseEncode(bytes);
    expect(publicKeyFromMultibase(multibaseKey)).toBeNull();
  });

  it("should return null for invalid key length", () => {
    const bytes = new Uint8Array(20);
    bytes[0] = 0x80;
    bytes[1] = 0x24;
    const multibaseKey = multibaseEncode(bytes);
    expect(publicKeyFromMultibase(multibaseKey)).toBeNull();
  });

  it("should convert a multibase-encoded P-384 key to a KeyObject", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const jwk = publicKey.export({ format: "jwk" });

    // x and y coordinates are 48 bytes each for P-384
    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
    const compressedPoint = Buffer.alloc(49);
    compressedPoint[0] = prefix;
    x.copy(compressedPoint, 1);

    // P-384 multicodec prefix: 0x81 0x24
    const multicodec = Buffer.alloc(2 + 49);
    multicodec[0] = 0x81;
    multicodec[1] = 0x24;
    compressedPoint.copy(multicodec, 2);

    const multibaseKey = multibaseEncode(multicodec);
    const result = publicKeyFromMultibase(multibaseKey);

    expect(result).not.toBeNull();
    expect(result!.type).toBe("public");
    expect(result!.asymmetricKeyType).toBe("ec");
    // Confirm the reconstructed key is actually P-384 (not accidentally P-256)
    const reconstructedJwk = result!.export({ format: "jwk" });
    expect(reconstructedJwk.crv).toBe("P-384");
  });

  it("should produce a P-384 key that can verify signatures", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const jwk = publicKey.export({ format: "jwk" });

    const x = Buffer.from(jwk.x!, "base64url");
    const y = Buffer.from(jwk.y!, "base64url");
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
    const compressedPoint = Buffer.alloc(49);
    compressedPoint[0] = prefix;
    x.copy(compressedPoint, 1);
    const multicodec = Buffer.alloc(2 + 49);
    multicodec[0] = 0x81;
    multicodec[1] = 0x24;
    compressedPoint.copy(multicodec, 2);
    const multibaseKey = multibaseEncode(multicodec);

    const signer = createSign("SHA384");
    signer.update("test data");
    const signature = signer.sign(privateKey);

    const reconstructedKey = publicKeyFromMultibase(multibaseKey)!;
    const verifier = createVerify("SHA384");
    verifier.update("test data");
    expect(verifier.verify(reconstructedKey, signature)).toBe(true);
  });

  it("should return null for a P-384 prefix with wrong compressed-key length", () => {
    const bytes = new Uint8Array(2 + 20);
    bytes[0] = 0x81;
    bytes[1] = 0x24;
    const multibaseKey = multibaseEncode(bytes);
    expect(publicKeyFromMultibase(multibaseKey)).toBeNull();
  });
});
