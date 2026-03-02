/**
 * Unified signing provider abstraction for the web UI.
 *
 * Provides factory functions that create WebSigner instances for each
 * signing method. The WebSigner interface allows the CredentialBuilder
 * to be signing-method agnostic.
 */

import type { SignerMetadata, WebSigner } from "./types";
import { pkcs11, oscert } from "./extension-client";
import { signData, base64urlDecode, base64urlEncode } from "./webcrypto";

// ---------------------------------------------------------------------------
// Helpers: base64url ↔ standard base64
// ---------------------------------------------------------------------------

/** Convert base64url to standard base64 (for extension protocol). */
function base64urlToBase64(b64url: string): string {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  return b64;
}

/** Convert standard base64 to base64url. */
function base64ToBase64url(b64: string): string {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// JWK signer (WebCrypto)
// ---------------------------------------------------------------------------

/**
 * Create a WebSigner that wraps the existing WebCrypto signData function.
 *
 * @param cryptoKey - a non-extractable CryptoKey from importKeyFile()
 * @param publicKeyId - the stable identifier from importKeyFile()
 */
export function createJwkSigner(
  cryptoKey: CryptoKey,
  publicKeyId: string,
): WebSigner {
  return {
    publicKeyId,
    metadata: { type: "jwk" },
    async sign(dataBase64url: string): Promise<string> {
      const data = base64urlDecode(dataBase64url);
      const sig = await signData(cryptoKey, data);
      return base64urlEncode(sig);
    },
  };
}

// ---------------------------------------------------------------------------
// PKCS#11 signer (via extension)
// ---------------------------------------------------------------------------

/**
 * Create a WebSigner that delegates signing to a PKCS#11 token via the
 * browser extension.
 *
 * @param signerId - signer session ID returned from pkcs11.connect()
 * @param metadata - signer metadata from pkcs11.connect()
 */
export function createPkcs11Signer(
  signerId: string,
  metadata: SignerMetadata,
): WebSigner {
  return {
    publicKeyId: metadata.id,
    metadata: { type: "pkcs11", label: metadata.label },
    async sign(dataBase64url: string): Promise<string> {
      const dataBase64 = base64urlToBase64(dataBase64url);
      const result = await pkcs11.sign(signerId, dataBase64);
      return base64ToBase64url(result.signature);
    },
  };
}

// ---------------------------------------------------------------------------
// OS Certificate signer (via extension)
// ---------------------------------------------------------------------------

/**
 * Create a WebSigner that delegates signing to an OS certificate store key
 * via the browser extension.
 *
 * @param signerId - signer session ID returned from oscert.connect()
 * @param metadata - signer metadata from oscert.connect()
 */
export function createOsCertSigner(
  signerId: string,
  metadata: SignerMetadata,
): WebSigner {
  return {
    publicKeyId: metadata.id,
    metadata: { type: "os-cert", label: metadata.label },
    async sign(dataBase64url: string): Promise<string> {
      const dataBase64 = base64urlToBase64(dataBase64url);
      const result = await oscert.sign(signerId, dataBase64);
      return base64ToBase64url(result.signature);
    },
  };
}
