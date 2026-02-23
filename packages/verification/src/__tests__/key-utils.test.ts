import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign, createVerify } from "node:crypto";
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

  it("should return null for non-P-256 multicodec prefix", () => {
    const bytes = new Uint8Array(35);
    bytes[0] = 0xed;
    bytes[1] = 0x01;
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
});
