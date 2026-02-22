export type {
  ProofOptions,
  PreparedProof,
  ProofConfig,
  SigningKey,
  VerificationResult,
  VerifyOptions,
} from "./types.js";

export {
  prepareProof,
  completeProof,
  signCredential,
  verifyProof,
  multibaseEncode,
  multibaseDecode,
} from "./data-integrity.js";

export { sha256, sha256Hex } from "./hash.js";
export { jcsCanonicalize, computeRevocationHash } from "./jcs.js";
