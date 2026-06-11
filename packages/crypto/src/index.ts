export type {
  SigningAlgorithm,
  ProofOptions,
  PreparedProof,
  ProofConfig,
  JwsProofOptions,
  JwsPreparedProof,
  SigningKey,
  VerificationResult,
  VerifyOptions,
  VcJwtSigningOptions,
  ProofFormat,
  SdJwtVcSigningOptions,
  SdJwtVcPreparedProof,
} from "./types.js";

export {
  prepareProof,
  completeProof,
  signCredential,
  verifyProof,
  multibaseEncode,
  multibaseDecode,
  derToRaw,
  rawToDer,
  canonicalize,
  computeSigningInput,
  precomputeProofConfig,
  prepareProofWithPrecomputedConfig,
} from "./data-integrity.js";
export type { PrecomputedProofConfig } from "./data-integrity.js";

export {
  prepareEdDsaProof,
  completeEdDsaProof,
  signCredentialEdDsa,
  verifyEdDsaProof,
} from "./eddsa-data-integrity.js";

export { sha256, sha256Hex, sha384 } from "./hash.js";

export {
  signCredentialJws,
  prepareJwsProof,
  completeJwsProof,
  signCredentialAuto,
  defaultProofFormat,
} from "./jws-proof.js";
export {
  jcsCanonicalize,
  computeRevocationHash,
  extractRevocationHashFromStatusId,
  resolveRevocationHash,
} from "./jcs.js";

export { signingAlgorithmToJwsAlg } from "./alg-mapping.js";
export { detectKeyAlgorithm, publicKeyFromEcBytes } from "./key-utils.js";
export {
  signCredentialSdJwtVc,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
} from "./sd-jwt-vc-signing.js";

export { signCredentialVcJwt, prepareVcJwtProof, completeVcJwtProof } from "./vc-jwt-signing.js";
export type { VcJwtPreparedProof } from "./vc-jwt-signing.js";

export type {
  SigningKeyProvider,
  SigningKeyInfo,
  PublicKeyJwk,
  LocalSigningKeyProviderOptions,
} from "./signing-key-provider.js";
export { LocalSigningKeyProvider } from "./signing-key-provider.js";
