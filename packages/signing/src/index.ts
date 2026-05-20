// Types
export type { Signer, SignerMetadata, KeyFormat } from "./types.js";
export type { SigningAlgorithm } from "@opencred/crypto";

// Software signer
export {
  createSoftwareSigner,
  createSoftwareSignerFromBuffer,
  buildSigner,
  buildSignerFromPfx,
  detectKeyFormat,
} from "./software-signer.js";

// Re-export detectKeyAlgorithm from its canonical home in @opencred/crypto
export { detectKeyAlgorithm } from "@opencred/crypto";

// In-process DID document cache for active signers (scale Tier 1 #3 — #571).
export {
  getCachedSignerDidDocument,
  signerDidDocumentCacheSize,
  resetSignerDidDocumentCache,
} from "./signer-did-cache.js";

// PFX parser
export type { PfxContents } from "./pfx-parser.js";
export { parsePfx } from "./pfx-parser.js";

// PKCS#11
export type { Pkcs11SignerOptions, Pkcs11SignerResult } from "./pkcs11-signer.js";
export { createPkcs11Signer, destroyPkcs11Signer } from "./pkcs11-signer.js";

export type {
  Pkcs11KeyInfo,
  Pkcs11CertInfo,
  Pkcs11SlotInfo,
  Pkcs11Session,
  Pkcs11Logger,
} from "./pkcs11-session.js";
export {
  initializePkcs11,
  finalizePkcs11,
  listSlots,
  openSession,
  closeSession,
  listKeys,
  listCertificates,
  findPrivateKey,
  setPkcs11Logger,
  resetPkcs11Logger,
} from "./pkcs11-session.js";

export {
  publicKeyFromEcPoint,
  publicKeyFromRsaComponents,
  rsaAlgorithmFromModulusBits,
  deriveDidJwkIdFromPublicKey,
  normalizeSignature,
  derCertToPem,
} from "./pkcs11-utils.js";

// Re-export key utilities from their canonical packages.
// These were previously wrapper functions in pkcs11-utils.ts.
export {
  deriveDidKeyId as deriveDidKeyIdFromPublicKey,
  computeKeyFingerprint as computeFingerprint,
} from "@opencred/did";
export { publicKeyFromEcBytes } from "@opencred/crypto";

// OS Cert Store
export type {
  OsCertInfo,
  OsCertProvider,
  OsCertSignerOptions,
  OsCertListResult,
} from "./os-cert-types.js";

export {
  createOsCertSigner,
  listOsCertificates,
  getProviderForPlatform,
} from "./os-cert-signer.js";

export { createMacOsCertProvider } from "./macos-cert-provider.js";
export type { MacOsNativeAddon } from "./macos-cert-provider.js";

export { createWindowsCertProvider } from "./windows-cert-provider.js";
export type { WindowsNativeAddon } from "./windows-cert-provider.js";
