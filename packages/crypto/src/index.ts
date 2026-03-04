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
} from "./data-integrity.js";

export { sha256, sha256Hex, sha384 } from "./hash.js";

export {
  signCredentialJws,
  prepareJwsProof,
  completeJwsProof,
  signCredentialAuto,
} from "./jws-proof.js";
export { jcsCanonicalize, computeRevocationHash } from "./jcs.js";

export {
  signCredentialVcJwt,
  prepareVcJwtProof,
  completeVcJwtProof,
} from "./vc-jwt-signing.js";
export type { VcJwtPreparedProof } from "./vc-jwt-signing.js";

export type {
  SigningKeyProvider,
  SigningKeyInfo,
  PublicKeyJwk,
  LocalSigningKeyProviderOptions,
} from "./signing-key-provider.js";
export { LocalSigningKeyProvider } from "./signing-key-provider.js";
