export type { DIDDocument, DIDResolutionResult, VerificationMethod, JWK } from "./types.js";
export type { DIDResolver } from "./resolver.js";
export {
  DIDKeyResolver,
  deriveDidKeyId,
  deriveDidKeyIdFromCompressedKey,
  getCompressedPublicKey,
  computeKeyFingerprint,
} from "./did-key.js";
export { DIDJwkResolver, encodeDidJwk, didJwkVerificationMethodId } from "./did-jwk.js";
export type { DIDWebFallbackResolver } from "./did-web.js";
export {
  DIDWebResolver,
  encodeDidWeb,
  didWebVerificationMethodId,
  didWebToUrl,
  generateDidWebDocument,
} from "./did-web.js";
export { CompositeDIDResolver } from "./composite-resolver.js";
