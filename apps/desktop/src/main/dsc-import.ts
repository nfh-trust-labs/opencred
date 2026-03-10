/**
 * DSC (Document Signer Certificate) import module for the OpenCred desktop app.
 *
 * Handles importing DSC files from PFX/P12 and PEM formats, extracting
 * certificate metadata, deriving DIDs from public keys, and providing
 * secure in-memory key storage.
 *
 * SECURITY INVARIANTS:
 *  - Key material is NEVER returned or logged. Only KeyMetadata (fingerprint,
 *    DID, algorithm) crosses module boundaries.
 *  - The KeyObject stays in the main process, stored in memory only,
 *    referenced by KeyMetadata.id.
 *  - Key material is NEVER serialised, transmitted, or included in error
 *    messages.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  X509Certificate,
  type KeyObject,
} from "node:crypto";
import { createRequire } from "node:module";
import { CryptoError } from "@opencred/shared";
import {
  deriveDidKeyIdFromPublicKey,
  deriveDidJwkIdFromPublicKey,
  computeFingerprint,
} from "@opencred/signing/pkcs11-utils";
import type { KeyMetadata } from "../shared/ipc-types.js";

// node-forge is a CJS module — use createRequire for resolution.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const nodeRequire = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const forge = nodeRequire("node-forge") as any;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CertificateMetadata {
  subject: { commonName?: string; organization?: string; country?: string };
  issuer: { commonName?: string; organization?: string; country?: string };
  serialNumber: string;
  validFrom: string;
  validUntil: string;
  keyAlgorithm: string;
  thumbprint: string;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validUntil: string;
}

export interface DscImportResult {
  keyMetadata: KeyMetadata;
  certificateMetadata: CertificateMetadata;
  certificateChain: CertificateInfo[];
}

// ---------------------------------------------------------------------------
// In-memory key store -- keys never leave this module
// ---------------------------------------------------------------------------

const keyStore = new Map<string, KeyObject>();
const metadataStore = new Map<string, KeyMetadata>();

// ---------------------------------------------------------------------------
// Key storage API
// ---------------------------------------------------------------------------

/**
 * Retrieve a stored key by its ID.
 * Used internally by the signing flow.
 */
export function getStoredKey(id: string): KeyObject | undefined {
  return keyStore.get(id);
}

/**
 * List metadata for all stored keys.
 * Returns only safe metadata.
 */
export function listStoredKeys(): KeyMetadata[] {
  return Array.from(metadataStore.values());
}

/**
 * Clear all stored keys. Used for testing and cleanup.
 */
export function clearKeyStore(): void {
  keyStore.clear();
  metadataStore.clear();
}

function storeKey(id: string, key: KeyObject, metadata: KeyMetadata): void {
  keyStore.set(id, key);
  metadataStore.set(id, metadata);
}

// ---------------------------------------------------------------------------
// Algorithm detection
// ---------------------------------------------------------------------------

function detectAlgorithmName(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" });

  if (jwk.kty === "EC") {
    if (jwk.crv === "P-256") return "ECDSA P-256";
    if (jwk.crv === "P-384") return "ECDSA P-384";
    return `ECDSA ${String(jwk.crv)}`;
  }

  if (jwk.kty === "OKP") {
    if (jwk.crv === "Ed25519") return "Ed25519";
    return `OKP ${String(jwk.crv)}`;
  }

  if (jwk.kty === "RSA") {
    const modulusBits = Buffer.from(jwk.n!, "base64url").length * 8;
    return `RSA-${modulusBits}`;
  }

  return String(jwk.kty);
}

function isEcKey(publicKey: KeyObject): boolean {
  const jwk = publicKey.export({ format: "jwk" });
  return jwk.kty === "EC" || jwk.kty === "OKP";
}

// ---------------------------------------------------------------------------
// DID derivation
// ---------------------------------------------------------------------------

/**
 * Derive a DID and verification method ID from a public key.
 *
 * EC keys (P-256, P-384, Ed25519) use did:key.
 * RSA keys use did:jwk.
 */
export function deriveDidFromPublicKey(
  publicKey: KeyObject,
): { did: string; verificationMethodId: string } {
  if (isEcKey(publicKey)) {
    const verificationMethodId = deriveDidKeyIdFromPublicKey(publicKey);
    const did = verificationMethodId.split("#")[0];
    return { did, verificationMethodId };
  }

  const verificationMethodId = deriveDidJwkIdFromPublicKey(publicKey);
  const did = verificationMethodId.split("#")[0];
  return { did, verificationMethodId };
}

// ---------------------------------------------------------------------------
// Certificate metadata extraction
// ---------------------------------------------------------------------------

/**
 * Parse an X.509 distinguished name string into components.
 * X509Certificate.subject/issuer returns "CN=...\nO=...\nC=..." format.
 */
function parseDN(dn: string): { commonName?: string; organization?: string; country?: string } {
  const fields: Record<string, string> = {};
  for (const line of dn.split("\n")) {
    const eqIndex = line.indexOf("=");
    if (eqIndex !== -1) {
      const key = line.substring(0, eqIndex).trim();
      const value = line.substring(eqIndex + 1).trim();
      fields[key] = value;
    }
  }

  return {
    commonName: fields["CN"],
    organization: fields["O"],
    country: fields["C"],
  };
}

function detectCertKeyAlgorithm(cert: X509Certificate): string {
  // cert.publicKey is already a KeyObject of type "public"
  return detectAlgorithmName(cert.publicKey);
}

/**
 * Extract metadata from an X.509 certificate.
 */
export function extractCertificateMetadata(cert: X509Certificate): CertificateMetadata {
  const subject = parseDN(cert.subject);
  const issuer = parseDN(cert.issuer);

  const derBuffer = Buffer.from(cert.raw);
  const thumbprint = createHash("sha256").update(derBuffer).digest("hex");
  const serialNumber = cert.serialNumber;

  return {
    subject,
    issuer,
    serialNumber,
    validFrom: new Date(cert.validFrom).toISOString(),
    validUntil: new Date(cert.validTo).toISOString(),
    keyAlgorithm: detectCertKeyAlgorithm(cert),
    thumbprint,
  };
}

function certPemToInfo(certPem: string): CertificateInfo {
  const cert = new X509Certificate(certPem);
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    validFrom: new Date(cert.validFrom).toISOString(),
    validUntil: new Date(cert.validTo).toISOString(),
  };
}

// ---------------------------------------------------------------------------
// PFX internal parsing
// ---------------------------------------------------------------------------

/**
 * Parse a PFX/P12 buffer using node-forge.
 */
function parsePfxBuffer(
  pfxBuffer: Buffer,
  password: string,
): { nodeKey: KeyObject; publicKey: KeyObject; certPems: string[] } {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let asn1: any;
  try {
    asn1 = forge.asn1.fromDer(pfxBuffer.toString("binary"));
  } catch {
    throw new CryptoError("Invalid PFX data: failed to parse ASN.1 structure");
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let p12: any;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);
  } catch {
    throw new CryptoError("Failed to decrypt PFX: wrong password or corrupted file");
  }

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBagList = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];
  if (!keyBagList || keyBagList.length === 0) {
    throw new CryptoError("PFX contains no key material");
  }

  const bag = keyBagList[0];
  let nodeKey: KeyObject;

  if (bag.key) {
    nodeKey = createPrivateKey(forge.pki.privateKeyToPem(bag.key));
  } else if (bag.asn1) {
    const derBytes = forge.asn1.toDer(bag.asn1);
    nodeKey = createPrivateKey({
      key: Buffer.from(derBytes.getBytes(), "binary"),
      format: "der",
      type: "pkcs8",
    });
  } else {
    throw new CryptoError("Failed to extract key from PFX");
  }

  const publicKey = createPublicKey(nodeKey);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certBagList = certBags[forge.pki.oids.certBag];
  const certPems: string[] = [];

  if (certBagList) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for (const cb of certBagList as any[]) {
      if (cb.cert) {
        certPems.push(forge.pki.certificateToPem(cb.cert));
      } else if (cb.asn1) {
        const derBytes = forge.asn1.toDer(cb.asn1);
        const b64 = Buffer.from(derBytes.getBytes(), "binary").toString("base64");
        const lines = b64.match(/.{1,64}/g) || [];
        certPems.push(
          `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`,
        );
      }
    }
  }

  return { nodeKey, publicKey, certPems };
}

// ---------------------------------------------------------------------------
// PFX import
// ---------------------------------------------------------------------------

/**
 * Import a PFX/P12 file and extract key metadata, certificate metadata,
 * and the certificate chain.
 *
 * The key is stored in the in-memory key store, referenced by its
 * verification method ID. It is NEVER returned or logged.
 */
export function importPfx(pfxBuffer: Buffer, password: string): DscImportResult {
  const { nodeKey, publicKey, certPems } = parsePfxBuffer(pfxBuffer, password);

  const algorithmName = detectAlgorithmName(publicKey);
  const fingerprint = computeFingerprint(publicKey);
  const { verificationMethodId } = deriveDidFromPublicKey(publicKey);

  const keyMetadata: KeyMetadata = {
    id: verificationMethodId,
    fingerprint,
    algorithm: algorithmName,
    importedAt: new Date().toISOString(),
    format: "pfx",
    source: "file",
  };

  storeKey(verificationMethodId, nodeKey, keyMetadata);

  let certificateMetadata: CertificateMetadata;
  const certificateChain: CertificateInfo[] = [];

  if (certPems.length > 0) {
    const firstCert = new X509Certificate(certPems[0]);
    certificateMetadata = extractCertificateMetadata(firstCert);

    for (const certPem of certPems) {
      certificateChain.push(certPemToInfo(certPem));
    }
  } else {
    certificateMetadata = {
      subject: {},
      issuer: {},
      serialNumber: "",
      validFrom: "",
      validUntil: "",
      keyAlgorithm: algorithmName,
      thumbprint: "",
    };
  }

  return {
    keyMetadata,
    certificateMetadata,
    certificateChain,
  };
}

// ---------------------------------------------------------------------------
// PEM import
// ---------------------------------------------------------------------------

/**
 * Extract PEM blocks from a concatenated PEM string.
 */
function extractPemBlocks(
  pemContent: string,
): { certificates: string[]; keyBlock: string | null } {
  const certificates: string[] = [];
  let keyBlock: string | null = null;

  const pemRegex = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;
  let match;

  while ((match = pemRegex.exec(pemContent)) !== null) {
    const type = match[1];
    const block = match[0];

    if (type === "CERTIFICATE") {
      certificates.push(block);
    } else if (
      type === "PRIVATE KEY" ||
      type === "EC PRIVATE KEY" ||
      type === "RSA PRIVATE KEY" ||
      type === "ENCRYPTED PRIVATE KEY"
    ) {
      keyBlock = block;
    }
  }

  return { certificates, keyBlock };
}

/**
 * Import a PEM file containing a key (and optionally certificates).
 *
 * The key is stored in the in-memory key store, referenced by its
 * verification method ID. It is NEVER returned or logged.
 */
export function importPem(pemContent: string): DscImportResult {
  const { certificates, keyBlock } = extractPemBlocks(pemContent);

  let parsedKey: KeyObject;
  try {
    if (keyBlock) {
      parsedKey = createPrivateKey(keyBlock);
    } else {
      parsedKey = createPrivateKey(pemContent);
    }
  } catch {
    throw new CryptoError(
      "Invalid PEM: failed to parse key from the provided content",
    );
  }

  const publicKey = createPublicKey(parsedKey);
  const algorithmName = detectAlgorithmName(publicKey);
  const fingerprint = computeFingerprint(publicKey);
  const { verificationMethodId } = deriveDidFromPublicKey(publicKey);

  const keyMetadata: KeyMetadata = {
    id: verificationMethodId,
    fingerprint,
    algorithm: algorithmName,
    importedAt: new Date().toISOString(),
    format: "pem",
    source: "file",
  };

  storeKey(verificationMethodId, parsedKey, keyMetadata);

  let certificateMetadata: CertificateMetadata;
  const certificateChain: CertificateInfo[] = [];

  if (certificates.length > 0) {
    const firstCert = new X509Certificate(certificates[0]);
    certificateMetadata = extractCertificateMetadata(firstCert);

    for (const certPem of certificates) {
      certificateChain.push(certPemToInfo(certPem));
    }
  } else {
    certificateMetadata = {
      subject: {},
      issuer: {},
      serialNumber: "",
      validFrom: "",
      validUntil: "",
      keyAlgorithm: algorithmName,
      thumbprint: "",
    };
  }

  return {
    keyMetadata,
    certificateMetadata,
    certificateChain,
  };
}
