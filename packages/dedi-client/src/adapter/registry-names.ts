export const REVOCATION_REGISTRY = "vc-revocation-registry";
export const PUBLIC_KEY_REGISTRY = "public_key_registry";
export const SCHEMA_REGISTRY = "schema_registry";
export const CONTEXT_REGISTRY = "context_registry";

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
