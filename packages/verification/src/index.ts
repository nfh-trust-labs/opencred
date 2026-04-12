export type {
  CredentialFormat,
  CredentialVerificationResult,
  VerificationCheck,
  VerificationInput,
  VerificationResultCode,
  VerifierConfig,
} from "./types.js";

export { verifyCredential, detectFormat } from "./verifier.js";
export { verifyDataIntegrity } from "./data-integrity.js";
export { verifyJwsProof } from "./jws-proof.js";
export { verifyVcJwt, extractVcJwtCredentialFields, crossValidateVcJwtClaims } from "./vc-jwt.js";
export type { VcJwtPayload } from "./vc-jwt.js";
export {
  verifySdJwtVc,
  parseSdJwtVc,
  decodeDisclosure,
  processDisclosures,
  extractSdJwtVcCredentialFields,
} from "./sd-jwt-vc.js";
export type {
  SdJwtVcComponents,
  SdJwtVcPayload,
  SdJwtVcVerifyOptions,
  Disclosure,
} from "./sd-jwt-vc.js";
export { checkDates, checkRevocation, checkBitstringStatusList } from "./checks.js";
export type { BitstringStatusListOptions } from "./checks.js";
export { checkX509Chain, loadCscaTrustStore } from "./x509-chain-check.js";
export type { LoadCscaTrustStoreOptions, X509ChainCheckOptions } from "./x509-chain-check.js";
export { CscaTrustStore } from "./csca-trust-store.js";
export type { CscaTrustStoreOptions, TrustStoreWarningCallback } from "./csca-trust-store.js";
export { publicKeyFromMultibase } from "./key-utils.js";
