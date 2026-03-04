export type { DIDDocument, DIDResolutionResult, VerificationMethod, JWK } from "./types.js";
export type { DIDResolver } from "./resolver.js";
export {
  DIDKeyResolver,
  deriveDidKeyId,
  deriveDidKeyIdFromCompressedKey,
  getCompressedPublicKey,
  computeKeyFingerprint,
} from "./did-key.js";
export {
  DIDJwkResolver,
  encodeDidJwk,
  didJwkVerificationMethodId,
} from "./did-jwk.js";
