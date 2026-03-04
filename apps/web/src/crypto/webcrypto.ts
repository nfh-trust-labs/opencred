/**
 * WebCrypto utilities for client-side signing (Interface Signing).
 *
 * Supports EC (P-256, P-384) and RSA (2048, 3072, 4096) keys imported from
 * JWK, PEM, or PFX/P12 files. All signing happens locally via SubtleCrypto.
 * Keys are imported as non-extractable CryptoKey handles — raw key material
 * is never stored in application state, displayed in the DOM, or logged.
 */

import * as forge from "node-forge";
import type { WebSigningAlgorithm } from "./types";

/** Result of importing a key file. */
export interface ImportedKeyResult {
  signingKey: CryptoKey;
  publicKeyId: string;
  algorithm: WebSigningAlgorithm;
  certificateChain?: string[];
  certificateInfo?: CertificateInfo;
}

/** Certificate information extracted from PFX imports. */
export interface CertificateInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validUntil: string;
  algorithm: string;
}

// ---------------------------------------------------------------------------
// JWK import (existing, widened to P-256/P-384/RSA)
// ---------------------------------------------------------------------------

/**
 * Import a JWK file's contents into a non-extractable CryptoKey.
 * Supports EC P-256, EC P-384, and RSA keys.
 */
export async function importKeyFile(
  fileContents: string,
): Promise<{ signingKey: CryptoKey; publicKeyId: string }> {
  const result = await importJwkFile(fileContents);
  return { signingKey: result.signingKey, publicKeyId: result.publicKeyId };
}

/**
 * Import a JWK file with full result including algorithm info.
 */
export async function importJwkFile(fileContents: string): Promise<ImportedKeyResult> {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(fileContents) as Record<string, unknown>;
  } catch {
    throw new Error("Invalid JSON");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("JWK must be a JSON object");
  }

  if (parsed.kty === "EC") {
    return importEcJwk(parsed);
  }
  if (parsed.kty === "RSA") {
    return importRsaJwk(parsed);
  }
  throw new Error('JWK kty must be "EC" or "RSA"');
}

async function importEcJwk(jwk: Record<string, unknown>): Promise<ImportedKeyResult> {
  const crv = jwk.crv as string;
  if (crv !== "P-256" && crv !== "P-384") {
    throw new Error('EC JWK crv must be "P-256" or "P-384"');
  }
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string" || typeof jwk.d !== "string") {
    throw new Error("EC JWK must contain x, y, and d fields (private key)");
  }

  const algorithm: WebSigningAlgorithm = crv;
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv, x: jwk.x, y: jwk.y, d: jwk.d },
    { name: "ECDSA", namedCurve: crv },
    false,
    ["sign"],
  );

  const publicKeyId = jwkToPublicId({ kty: "EC", crv, x: jwk.x as string, y: jwk.y as string });

  // Defense in depth: zero private key component.
  (jwk as Record<string, string>).d = "";

  return { signingKey, publicKeyId, algorithm };
}

async function importRsaJwk(jwk: Record<string, unknown>): Promise<ImportedKeyResult> {
  if (typeof jwk.n !== "string" || typeof jwk.e !== "string" || typeof jwk.d !== "string") {
    throw new Error("RSA JWK must contain n, e, and d fields (private key)");
  }

  const modulusBits = base64urlDecode(jwk.n as string).length * 8;
  let algorithm: WebSigningAlgorithm;
  if (modulusBits <= 2048) algorithm = "RSA-2048";
  else if (modulusBits <= 3072) algorithm = "RSA-3072";
  else algorithm = "RSA-4096";

  const signingKey = await crypto.subtle.importKey(
    "jwk",
    jwk as JsonWebKey,
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const publicKeyId = jwkToPublicId({ kty: "RSA", n: jwk.n as string, e: jwk.e as string });

  // Defense in depth: zero private components.
  for (const field of ["d", "p", "q", "dp", "dq", "qi"]) {
    if (field in jwk) (jwk as Record<string, string>)[field] = "";
  }

  return { signingKey, publicKeyId, algorithm };
}

// ---------------------------------------------------------------------------
// PEM import
// ---------------------------------------------------------------------------

/**
 * Import a PEM-encoded private key into a non-extractable CryptoKey.
 */
export async function importPemFile(pemString: string): Promise<ImportedKeyResult> {
  const lines = pemString.trim().split("\n");
  const header = lines[0];

  if (!header.includes("BEGIN") || !header.includes("PRIVATE KEY")) {
    throw new Error("Invalid PEM: expected a private key file");
  }

  // Strip PEM headers and decode
  const b64 = lines
    .filter((l) => !l.startsWith("-----"))
    .join("");
  const derBytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  // Try EC first (P-256, P-384), then RSA
  try {
    return await importEcPkcs8(derBytes);
  } catch {
    // Not EC, try RSA
  }

  return importRsaPkcs8(derBytes);
}

async function importEcPkcs8(der: Uint8Array): Promise<ImportedKeyResult> {
  const derBuffer = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer;
  // Try P-256 first
  for (const crv of ["P-256", "P-384"] as const) {
    try {
      const key = await crypto.subtle.importKey(
        "pkcs8",
        derBuffer,
        { name: "ECDSA", namedCurve: crv },
        true, // extractable temporarily to get public components
        ["sign"],
      );

      // Export as JWK to get public components for ID
      const jwk = await crypto.subtle.exportKey("jwk", key);

      // Re-import as non-extractable
      const signingKey = await crypto.subtle.importKey(
        "pkcs8",
        derBuffer,
        { name: "ECDSA", namedCurve: crv },
        false,
        ["sign"],
      );

      const publicKeyId = jwkToPublicId({
        kty: "EC",
        crv,
        x: jwk.x!,
        y: jwk.y!,
      });

      return { signingKey, publicKeyId, algorithm: crv };
    } catch {
      continue;
    }
  }
  throw new Error("Not an EC key");
}

async function importRsaPkcs8(der: Uint8Array): Promise<ImportedKeyResult> {
  const derBuffer = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer;
  const key = await crypto.subtle.importKey(
    "pkcs8",
    derBuffer,
    { name: "RSA-PSS", hash: "SHA-256" },
    true,
    ["sign"],
  );

  const jwk = await crypto.subtle.exportKey("jwk", key);
  const modulusBits = base64urlDecode(jwk.n!).length * 8;
  let algorithm: WebSigningAlgorithm;
  if (modulusBits <= 2048) algorithm = "RSA-2048";
  else if (modulusBits <= 3072) algorithm = "RSA-3072";
  else algorithm = "RSA-4096";

  // Re-import as non-extractable
  const signingKey = await crypto.subtle.importKey(
    "pkcs8",
    derBuffer,
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const publicKeyId = jwkToPublicId({ kty: "RSA", n: jwk.n!, e: jwk.e! });

  return { signingKey, publicKeyId, algorithm };
}

// ---------------------------------------------------------------------------
// PFX/P12 import (via node-forge in browser)
// ---------------------------------------------------------------------------

/**
 * Import a PKCS#12 (PFX/P12) file with password.
 * Returns the signing key, certificate chain, and certificate info.
 */
export async function importPfxFile(
  buffer: ArrayBuffer,
  password: string,
): Promise<ImportedKeyResult> {
  const binaryString = Array.from(new Uint8Array(buffer))
    .map((b) => String.fromCharCode(b))
    .join("");

  let p12Asn1: forge.asn1.Asn1;
  try {
    p12Asn1 = forge.asn1.fromDer(binaryString);
  } catch {
    throw new Error("Invalid PFX/P12 file format");
  }

  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
  } catch {
    throw new Error("Failed to decrypt PFX — check the password");
  }

  // Extract private key
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];
  if (!keyBag || keyBag.length === 0 || !keyBag[0].key) {
    throw new Error("PFX does not contain a private key");
  }
  const forgeKey = keyBag[0].key;

  // Extract certificates for chain
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certs = certBags[forge.pki.oids.certBag] ?? [];
  const certificateChain = certs
    .filter((bag) => bag.cert)
    .map((bag) => forge.pki.certificateToPem(bag.cert!));

  // Detect algorithm from key type
  const keyPem = forge.pki.privateKeyToPem(forgeKey);

  // Try importing as EC then RSA
  let result: ImportedKeyResult;
  try {
    result = await importPemFile(keyPem);
  } catch {
    throw new Error("Unsupported key type in PFX");
  }

  // Extract certificate info from the first cert (the end-entity cert)
  let certificateInfo: CertificateInfo | undefined;
  if (certs.length > 0 && certs[0].cert) {
    const cert = certs[0].cert;
    certificateInfo = {
      subject: cert.subject.attributes
        .map((a) => `${a.shortName}=${a.value}`)
        .join(", "),
      issuer: cert.issuer.attributes
        .map((a) => `${a.shortName}=${a.value}`)
        .join(", "),
      validFrom: cert.validity.notBefore.toISOString(),
      validUntil: cert.validity.notAfter.toISOString(),
      algorithm: result.algorithm,
    };
  }

  return {
    ...result,
    certificateChain: certificateChain.length > 0 ? certificateChain : undefined,
    certificateInfo,
  };
}

// ---------------------------------------------------------------------------
// Multi-algorithm signing
// ---------------------------------------------------------------------------

/**
 * Extract the public key component (x, y) from a JWK-like object.
 * Returns a base64url-encoded identifier. Does NOT require the `d` field.
 */
export function extractPublicKeyId(jwk: { x: string; y: string }): string {
  return jwkToPublicId({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y });
}

/**
 * Sign data using the appropriate algorithm for the key.
 * - EC P-256: ECDSA + SHA-256 → 64-byte raw r||s
 * - EC P-384: ECDSA + SHA-384 → 96-byte raw r||s
 * - RSA: RSA-PSS + SHA-256
 */
export async function signData(
  key: CryptoKey,
  data: Uint8Array,
  algorithm?: WebSigningAlgorithm,
): Promise<Uint8Array> {
  if (algorithm?.startsWith("RSA")) {
    const sig = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      key,
      data as Uint8Array<ArrayBuffer>,
    );
    return new Uint8Array(sig);
  }

  if (algorithm === "P-384") {
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-384" },
      key,
      data as Uint8Array<ArrayBuffer>,
    );
    return new Uint8Array(sig);
  }

  // Default: P-256
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(sig);
}

// ---------------------------------------------------------------------------
// Base64url utilities
// ---------------------------------------------------------------------------

export function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// Auto-detect file format
// ---------------------------------------------------------------------------

/** Detect the key file format from content. */
export function detectKeyFormat(
  content: ArrayBuffer | string,
): "jwk" | "pem" | "pfx" | "unknown" {
  if (typeof content === "string") {
    const trimmed = content.trim();
    if (trimmed.startsWith("{")) return "jwk";
    if (trimmed.startsWith("-----")) return "pem";
    return "unknown";
  }

  // Binary content — check PFX magic bytes or PEM text
  const bytes = new Uint8Array(content);
  // PFX/P12 files start with ASN.1 SEQUENCE tag (0x30)
  if (bytes.length > 2 && bytes[0] === 0x30) {
    return "pfx";
  }

  // Try to decode as text to check for PEM
  try {
    const text = new TextDecoder().decode(bytes);
    if (text.trim().startsWith("-----")) return "pem";
    if (text.trim().startsWith("{")) return "jwk";
  } catch {
    // Not text
  }

  return "unknown";
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function jwkToPublicId(pub: Record<string, string>): string {
  const safeFields = Object.entries(pub)
    .filter(([k]) => !["d", "p", "q", "dp", "dq", "qi"].includes(k))
    .reduce<Record<string, string>>((acc, [k, v]) => { acc[k] = v; return acc; }, {});
  return btoa(JSON.stringify(safeFields))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
