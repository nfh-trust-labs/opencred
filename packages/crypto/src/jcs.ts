import { canonicalize } from "json-canonicalize";
import { sha256Hex } from "./hash.js";

/**
 * Canonicalize a JSON object using JCS (JSON Canonicalization Scheme, RFC 8785).
 * @param obj — The object to canonicalize.
 * @returns The canonical JSON string per RFC 8785.
 */
export function jcsCanonicalize(obj: unknown): string {
  return canonicalize(obj);
}

/**
 * Compute a hex-encoded SHA-256 hash of the JCS-canonicalized form of an object.
 * Used for revocation registry hashing and deterministic credential identifiers.
 * @param credential — The credential or object to hash.
 * @returns Lowercase hex SHA-256 of the JCS-canonicalized form.
 */
export function computeRevocationHash(credential: unknown): string {
  const canonical = canonicalize(credential);
  return sha256Hex(canonical);
}

/**
 * Extract the revocation hash that OpenCred's issuance pipeline embeds in
 * `credential.credentialStatus.id`.
 *
 * The canonical issuance paths (server `/credentials/issue`, server batch
 * engine, and the Electron desktop client) all write the credential status
 * lookup URL as:
 *
 *     <revocationRegistryUrl-with-/dedi/lookup/>/<64-char lowercase hex hash>
 *
 * Verifiers and revocation-submit handlers MUST use this embedded hash when
 * querying or writing to the DeDi registry — not a recomputed canonical hash
 * of the whole credential — because the embedded hash is the single source of
 * truth the issuer committed to at signing time. Recomputing a canonical
 * hash at verification time is silently wrong: the two hash schemes produce
 * different values, so the query misses the record and a revoked credential
 * appears valid.
 *
 * @param credential — The parsed credential object to inspect.
 * @returns The extracted 64-character lowercase hex hash, or `null` when the
 *   credential has no `credentialStatus.id`, the id is not a valid URL, or the
 *   last path segment is not a well-formed lowercase hex SHA-256 digest.
 */
export function extractRevocationHashFromStatusId(credential: unknown): string | null {
  if (typeof credential !== "object" || credential === null) return null;
  const status = (credential as Record<string, unknown>)["credentialStatus"];
  if (typeof status !== "object" || status === null) return null;
  const rawId = (status as Record<string, unknown>)["id"];
  if (typeof rawId !== "string" || rawId.length === 0) return null;
  let parsed: URL;
  try {
    parsed = new URL(rawId);
  } catch {
    return null;
  }
  const segments = parsed.pathname.split("/").filter((s) => s.length > 0);
  const last = segments[segments.length - 1];
  if (!last) return null;
  if (!/^[a-f0-9]{64}$/.test(last)) return null;
  return last;
}

/**
 * Resolve the revocation hash for a credential.
 *
 * Prefers the hash embedded in `credentialStatus.id` — the single source of
 * truth for credentials issued by OpenCred — and falls back to
 * {@link computeRevocationHash} when the credential carries no well-formed
 * `credentialStatus.id`. The fallback preserves interop with credentials
 * issued by other implementations that may hash the whole credential.
 */
export function resolveRevocationHash(credential: unknown): string {
  const embedded = extractRevocationHashFromStatusId(credential);
  if (embedded !== null) return embedded;
  return computeRevocationHash(credential);
}
