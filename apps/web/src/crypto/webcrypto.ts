/**
 * WebCrypto utilities for client-side ECDSA P-256 signing (Interface Signing).
 *
 * SECURITY: The private key never leaves the browser. All signing happens
 * locally via SubtleCrypto. The key is imported as non-extractable.
 */

export interface EcJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  d: string;
}

/**
 * Import an ECDSA P-256 private key from JWK into a non-extractable CryptoKey.
 */
export async function importPrivateKey(jwk: EcJwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
      d: jwk.d,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false, // non-extractable
    ["sign"],
  );
}

/**
 * Extract the public key component (x, y) from a private key JWK.
 * Returns a JWK string identifier suitable for the API's `publicKey` field.
 */
export function extractPublicKeyId(jwk: EcJwk): string {
  return btoa(JSON.stringify({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Sign data using ECDSA P-256 with SHA-256. Returns raw r||s signature (64 bytes).
 */
export async function signData(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  // Copy to a plain ArrayBuffer to satisfy TypeScript's BufferSource constraint
  const buffer = new ArrayBuffer(data.byteLength);
  new Uint8Array(buffer).set(data);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, buffer);
  return new Uint8Array(sig);
}

/**
 * Decode a base64url-encoded string to Uint8Array.
 */
export function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode a Uint8Array as base64url.
 */
export function base64urlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Parse a JWK JSON string into an EcJwk object with basic validation.
 */
export function parseJwk(json: string): EcJwk {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("Invalid JSON");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("JWK must be a JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.kty !== "EC") {
    throw new Error('JWK kty must be "EC"');
  }
  if (obj.crv !== "P-256") {
    throw new Error('JWK crv must be "P-256"');
  }
  if (typeof obj.x !== "string" || typeof obj.y !== "string" || typeof obj.d !== "string") {
    throw new Error("JWK must contain x, y, and d fields (private key)");
  }
  return { kty: "EC", crv: "P-256", x: obj.x, y: obj.y, d: obj.d };
}
