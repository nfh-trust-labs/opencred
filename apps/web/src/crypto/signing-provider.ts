/**
 * Unified signing provider abstraction for the web UI.
 *
 * Provides factory functions that create WebSigner instances for each
 * signing method. The WebSigner interface allows the CredentialBuilder
 * to be signing-method agnostic.
 */

import type { SignerMetadata, WebSigner, WebSigningAlgorithm } from "./types";
import { pkcs11, oscert } from "./extension-client";
import { signData, base64urlDecode, base64urlEncode } from "./webcrypto";

// ---------------------------------------------------------------------------
// Helpers: base64url <-> standard base64
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
// JWK / PEM / PFX signer (WebCrypto)
// ---------------------------------------------------------------------------

/**
 * Create a WebSigner that wraps a WebCrypto CryptoKey.
 * Works for JWK, PEM, and PFX-imported keys.
 */
export function createJwkSigner(
  cryptoKey: CryptoKey,
  publicKeyId: string,
  algorithm: WebSigningAlgorithm = "P-256",
  options?: { type?: "jwk" | "pfx" | "pem"; certificateChain?: string[]; label?: string },
): WebSigner {
  return {
    publicKeyId,
    algorithm,
    certificateChain: options?.certificateChain,
    metadata: { type: options?.type ?? "jwk", label: options?.label },
    async sign(dataBase64url: string): Promise<string> {
      const data = base64urlDecode(dataBase64url);
      const sig = await signData(cryptoKey, data, algorithm);
      return base64urlEncode(sig);
    },
  };
}

// ---------------------------------------------------------------------------
// Extension-backed signers (PKCS#11 and OS cert)
// ---------------------------------------------------------------------------

function createExtensionSigner(
  signerId: string,
  metadata: SignerMetadata,
  type: "pkcs11" | "os-cert",
  signFn: (signerId: string, dataBase64: string) => Promise<{ signature: string }>,
): WebSigner {
  return {
    publicKeyId: metadata.id,
    algorithm: metadata.algorithm,
    certificateChain: metadata.certificateChain,
    metadata: { type, label: metadata.label },
    async sign(dataBase64url: string): Promise<string> {
      const dataBase64 = base64urlToBase64(dataBase64url);
      const result = await signFn(signerId, dataBase64);
      return base64ToBase64url(result.signature);
    },
  };
}

export function createPkcs11Signer(signerId: string, metadata: SignerMetadata): WebSigner {
  return createExtensionSigner(signerId, metadata, "pkcs11", pkcs11.sign);
}

export function createOsCertSigner(signerId: string, metadata: SignerMetadata): WebSigner {
  return createExtensionSigner(signerId, metadata, "os-cert", oscert.sign);
}
