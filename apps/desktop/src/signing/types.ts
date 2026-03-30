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
 * For did:web issuers the verification method is the DID itself suffixed with
 * the well-known key fragment (`#key-0`).  For all other DID methods the
 * signer's own `id` (typically a did:key URI) is used directly.
 */
export function deriveVerificationMethod(
  issuerDid: string | undefined,
  signerId: string,
): string {
  return issuerDid?.startsWith("did:web:")
    ? `${issuerDid}${DID_WEB_DEFAULT_KEY_FRAGMENT}`
    : signerId;
}
