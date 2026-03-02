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
export { verifyVcJwt, extractVcJwtCredentialFields } from "./vc-jwt.js";
export type { VcJwtPayload } from "./vc-jwt.js";
export {
  verifySdJwtVc,
  parseSdJwtVc,
  decodeDisclosure,
  processDisclosures,
  extractSdJwtVcCredentialFields,
} from "./sd-jwt-vc.js";
export type { SdJwtVcComponents, SdJwtVcPayload, SdJwtVcVerifyOptions, Disclosure } from "./sd-jwt-vc.js";
export { checkDates, checkRevocation, checkBitstringStatusList } from "./checks.js";
export { checkDelegationChain } from "./delegation-check.js";
export type { DelegationCheckOptions } from "./delegation-check.js";
export { publicKeyFromMultibase } from "./key-utils.js";
