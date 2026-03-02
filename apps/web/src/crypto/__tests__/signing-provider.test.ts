import { describe, it, expect, vi } from "vitest";
import {
  createJwkSigner,
  createPkcs11Signer,
  createOsCertSigner,
} from "../signing-provider";
import { base64urlEncode, base64urlDecode } from "../webcrypto";
import type { SignerMetadata } from "../types";

// Mock the extension client so tests don't need postMessage
vi.mock("../extension-client", () => ({
  pkcs11: {
    sign: vi.fn(),
  },
  oscert: {
    sign: vi.fn(),
  },
}));

import { pkcs11, oscert } from "../extension-client";

const mockPkcs11Sign = vi.mocked(pkcs11.sign);
const mockOscertSign = vi.mocked(oscert.sign);

describe("createJwkSigner", () => {
  it("sign() produces valid base64url signature", async () => {
    // Generate a real P-256 key pair for integration test
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );

    const signer = createJwkSigner(keyPair.privateKey, "test-key-id");

    const data = new TextEncoder().encode("hello world");
    const dataB64url = base64urlEncode(data);
    const sigB64url = await signer.sign(dataB64url);

    // Signature should be base64url (no +, /, or =)
    expect(sigB64url).not.toContain("+");
    expect(sigB64url).not.toContain("/");
    expect(sigB64url).not.toContain("=");

    // Decode and verify the signature is 64 bytes (P-256 r||s)
    const sigBytes = base64urlDecode(sigB64url);
    expect(sigBytes.length).toBe(64);

    // Verify with the public key
    const sigBuf = new ArrayBuffer(sigBytes.byteLength);
    new Uint8Array(sigBuf).set(sigBytes);
    const dataBuf = new ArrayBuffer(data.byteLength);
    new Uint8Array(dataBuf).set(data);
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.publicKey,
      sigBuf,
      dataBuf,
    );
    expect(valid).toBe(true);
  });

  it("has correct metadata.type", () => {
    // Use a dummy key — we only check metadata, not signing
    const signer = createJwkSigner({} as CryptoKey, "test-key-id");
    expect(signer.metadata.type).toBe("jwk");
    expect(signer.publicKeyId).toBe("test-key-id");
  });
});

describe("createPkcs11Signer", () => {
  const metadata: SignerMetadata = {
    id: "did:key:z6Mkp...",
    algorithm: "P-256",
    type: "pkcs11",
    fingerprint: "abc123",
    label: "YubiKey Token",
  };

  it("sign() calls extension client with correct base64", async () => {
    // Extension expects standard base64, not base64url
    // Input: base64url "AQ-_" (bytes [1, 15, 191])
    // Expected standard base64: "AQ+/" (with padding "AQ+/")
    mockPkcs11Sign.mockResolvedValueOnce({ signature: "AQID" });

    const signer = createPkcs11Signer("signer-123", metadata);
    const result = await signer.sign("AQ-_");

    expect(mockPkcs11Sign).toHaveBeenCalledWith("signer-123", "AQ+/");
    // "AQID" in standard base64 → "AQID" in base64url (no change needed here)
    expect(result).toBe("AQID");
  });

  it("has correct metadata", () => {
    const signer = createPkcs11Signer("signer-123", metadata);
    expect(signer.metadata.type).toBe("pkcs11");
    expect(signer.metadata.label).toBe("YubiKey Token");
    expect(signer.publicKeyId).toBe("did:key:z6Mkp...");
  });
});

describe("createOsCertSigner", () => {
  const metadata: SignerMetadata = {
    id: "did:key:z6Mkq...",
    algorithm: "P-256",
    type: "os-cert",
    fingerprint: "def456",
    label: "macOS Keychain",
  };

  it("sign() calls extension client with correct base64", async () => {
    mockOscertSign.mockResolvedValueOnce({ signature: "BAUG" });

    const signer = createOsCertSigner("signer-456", metadata);
    const result = await signer.sign("AQ-_");

    expect(mockOscertSign).toHaveBeenCalledWith("signer-456", "AQ+/");
    expect(result).toBe("BAUG");
  });

  it("has correct metadata", () => {
    const signer = createOsCertSigner("signer-456", metadata);
    expect(signer.metadata.type).toBe("os-cert");
    expect(signer.metadata.label).toBe("macOS Keychain");
    expect(signer.publicKeyId).toBe("did:key:z6Mkq...");
  });
});

describe("base64url ↔ base64 conversion", () => {
  it("converts base64url to standard base64 via round-trip", async () => {
    // Test with bytes that produce +, /, and = in standard base64
    const bytes = new Uint8Array([0, 15, 191, 255, 128, 64]);
    const b64url = base64urlEncode(bytes);

    // base64url should not contain +, /, =
    expect(b64url).not.toContain("+");
    expect(b64url).not.toContain("/");
    expect(b64url).not.toContain("=");

    // Round-trip back
    const decoded = base64urlDecode(b64url);
    expect(decoded).toEqual(bytes);
  });

  it("all signers have correct metadata.type", () => {
    const jwk = createJwkSigner({} as CryptoKey, "id-1");
    expect(jwk.metadata.type).toBe("jwk");

    const p11 = createPkcs11Signer("s1", {
      id: "id-2",
      algorithm: "P-256",
      type: "pkcs11",
      fingerprint: "f",
    });
    expect(p11.metadata.type).toBe("pkcs11");

    const cert = createOsCertSigner("s2", {
      id: "id-3",
      algorithm: "P-256",
      type: "os-cert",
      fingerprint: "f",
    });
    expect(cert.metadata.type).toBe("os-cert");
  });
});
