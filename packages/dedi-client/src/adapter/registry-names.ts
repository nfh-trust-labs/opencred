export const REVOCATION_REGISTRY = "vc-revocation-registry";

/**
 * Per-key registry. One record per signing key, keyed by
 * `verificationMethodToRecordName(verificationMethod)`. Holds the key's
 * status (`active` / `rotated` / `revoked`) plus the public key material —
 * the source of truth a verifier consults to answer "is this key live?".
 *
 * Replaces the old `public_key_registry` (one record per DID). See
 * `docs/decisions/dedi-key-registry-redesign.md`.
 */
export const OPENCRED_KEY_REGISTRY = "opencred-key-registry";

export const SCHEMA_REGISTRY = "schema_registry";
export const CONTEXT_REGISTRY = "context_registry";

/**
 * Slugify a DID or verification-method string into a DeDi record name.
 *
 * DeDi record names can't contain `:` or `#`, so both are replaced with
 * `-`. A bare DID (`did:web:acme.com`) and a verification method
 * (`did:web:acme.com#key-0`) slugify to distinct names
 * (`did-web-acme.com` vs `did-web-acme.com-key-0`); they also live in
 * different registries, so there is no cross-registry collision risk.
 */
function slugForDeDi(value: string): string {
  return value.replace(/[:#]/g, "-");
}

/**
 * Convert a verification method (the key's full `id`, e.g.
 * `did:web:acme.com#key-0` or a long `did:key:...#z...` fragment) into its
 * `opencred-key-registry` record name.
 *
 * @example
 * verificationMethodToRecordName("did:web:acme.com#key-0")
 * // "did-web-acme.com-key-0"
 */
export function verificationMethodToRecordName(verificationMethod: string): string {
  return slugForDeDi(verificationMethod);
}

/**
 * Convert a schemaId + version into a DeDi record name.
 *
 * v1 catalogue schema IDs are path-shaped (e.g., "functional-identity/v1",
 * "traceability/commercial-invoice/v1") and already carry a version suffix.
 * Record names can't contain "/", and we don't want to double-append
 * "-v1" on top of an ID that already ends in "/v1".
 */
export function schemaToRecordName(schemaId: string, version: string): string {
  const slug = schemaId.replace(/\//g, "-");
  const suffix = `-v${version}`;
  return slug.endsWith(suffix) ? slug : `${slug}${suffix}`;
}

export function contextToRecordName(schemaId: string, version: string): string {
  const slug = schemaId.replace(/\//g, "-");
  const suffix = `-v${version}`;
  const base = slug.endsWith(suffix) ? slug.slice(0, -suffix.length) : slug;
  return `${base}-ctx-v${version}`;
}
