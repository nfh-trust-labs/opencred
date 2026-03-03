/**
 * WebCrypto utilities for client-side ECDSA P-256 signing (Interface Signing).
 *
 * SECURITY: The private key never leaves the browser. All signing happens
 * locally via SubtleCrypto. Keys are imported as non-extractable CryptoKey
 * handles — raw key material (the JWK `d` field) is never stored in
 * application state, displayed in the DOM, or logged.
 */

/** Internal-only JWK shape used during import. Never exported. */
interface EcPrivateJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  d: string;
}

/** Public-only JWK shape (no `d` field). Safe to export / display. */
interface EcPublicJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

/**
 * Import a JWK file's contents into a non-extractable CryptoKey.
 *
 * The caller reads the file to a string, passes it here, then discards the
 * string. The returned CryptoKey handle is the only artefact retained.
 *
 * @param fileContents - raw JSON text of a JWK file (must be ECDSA P-256)
 * @returns the signing CryptoKey and a stable public key identifier
 */
export async function importKeyFile(
  fileContents: string,
): Promise<{ signingKey: CryptoKey; publicKeyId: string }> {
  const parsed = parseJwkInternal(fileContents);

  const signingKey = await crypto.subtle.importKey(
    "jwk",
    {
      kty: parsed.kty,
      crv: parsed.crv,
      x: parsed.x,
      y: parsed.y,
      d: parsed.d,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false, // non-extractable
    ["sign"],
  );

  // Derive the public key identifier from the public components only.
  const publicKeyId = publicJwkToId({ kty: "EC", crv: "P-256", x: parsed.x, y: parsed.y });

  // Defense in depth: zero the private key component now that import is complete.
  parsed.d = "";

  return { signingKey, publicKeyId };
}

/**
 * Extract the public key component (x, y) from a JWK-like object.
 * Returns a base64url-encoded identifier. Does NOT require the `d` field.
 */
export function extractPublicKeyId(jwk: { x: string; y: string }): string {
  return publicJwkToId({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y });
}

/**
 * Sign data using ECDSA P-256 with SHA-256. Returns raw r||s signature (64 bytes).
 */
export async function signData(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    data as Uint8Array<ArrayBuffer>,
  );
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
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse a JWK JSON string with validation. Internal only — never exported.
 * The result contains the `d` field which must not leak into React state.
 */
function parseJwkInternal(json: string): EcPrivateJwk {
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

/**
 * Produce a stable base64url identifier from the public components of a JWK.
 */
function publicJwkToId(pub: EcPublicJwk): string {
  return btoa(JSON.stringify({ kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
