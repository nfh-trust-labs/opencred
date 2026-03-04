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
  detectKeyAlgorithm,
} from "./software-signer.js";

// PFX parser
export type { PfxContents } from "./pfx-parser.js";
export { parsePfx } from "./pfx-parser.js";

// PKCS#11
export type { Pkcs11SignerOptions, Pkcs11SignerResult } from "./pkcs11-signer.js";
export { createPkcs11Signer, destroyPkcs11Signer } from "./pkcs11-signer.js";

export type { Pkcs11KeyInfo, Pkcs11CertInfo, Pkcs11SlotInfo, Pkcs11Session } from "./pkcs11-session.js";
export {
  initializePkcs11,
  finalizePkcs11,
  listSlots,
  openSession,
  closeSession,
  listKeys,
  listCertificates,
  findPrivateKey,
} from "./pkcs11-session.js";

export {
  publicKeyFromEcPoint,
  publicKeyFromRsaComponents,
  rsaAlgorithmFromModulusBits,
  deriveDidKeyIdFromPublicKey,
  deriveDidJwkIdFromPublicKey,
  computeFingerprint,
  normalizeSignature,
  derCertToPem,
} from "./pkcs11-utils.js";

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
