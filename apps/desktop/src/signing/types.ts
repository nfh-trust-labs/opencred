import { didWebVerificationMethodIdForIndex } from "@opencred/did";

export type { Signer, SignerMetadata, KeyFormat } from "@opencred/signing/types";

/**
 * Default fragment appended to did:web DIDs when constructing a verification
 * method identifier.  Matches the convention used by the DeDi registry and
 * the did:web specification's "first key" shorthand.
 */
export const DID_WEB_DEFAULT_KEY_FRAGMENT = "#key-0";

/**
 * Derive the verification method identifier for a credential proof.
 *
 * For did:web issuers the verification method is the DID suffixed with the
 * sequential key fragment `#key-<keyIndex>` (default `#key-0`). After a
 * rotation the issuer signs under the new key's index, so the fragment must
 * match the index that key was published at in DeDi and that appears in the
 * did.json — otherwise a verifier resolves the wrong key. For all other DID
 * methods the signer's own `id` (typically a did:key URI) is used directly.
 *
 * @param issuerDid - The issuer DID (did:web:... or did:key:...).
 * @param signerId - The local signer id (used for non-did:web methods).
 * @param keyIndex - The active key's sequential index (did:web only). Default 0.
 */
export function deriveVerificationMethod(
  issuerDid: string | undefined,
  signerId: string,
  keyIndex = 0,
): string {
  return issuerDid?.startsWith("did:web:")
    ? didWebVerificationMethodIdForIndex(issuerDid, keyIndex)
    : signerId;
}
