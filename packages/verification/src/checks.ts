import { resolve4, resolve6 } from "node:dns/promises";
import { isIP } from "node:net";
import { promisify } from "node:util";
import { gunzip as gunzipCb } from "node:zlib";
import type { DeDiClient } from "@opencred/dedi-client";
import { DeDiClientError } from "@opencred/dedi-client";
import { resolveRevocationHash } from "@opencred/crypto";
import type { DIDResolver } from "@opencred/did";
import { fetchWithPinnedIp, isPrivateIP } from "@opencred/shared";
import { verifyDataIntegrity } from "./data-integrity.js";
import type { VerifiableCredential } from "@opencred/vc-core";
import type { VerificationCheck } from "./types.js";

const gunzip = promisify(gunzipCb);

/** Maximum compressed encodedList size in bytes (1 MB). */
const MAX_COMPRESSED_SIZE = 1_048_576;

/**
 * Check validFrom / validUntil date constraints.
 * Returns a check result indicating whether the credential is within its validity period.
 */
export function checkDates(
  validFrom?: string,
  validUntil?: string,
  now: Date = new Date(),
): VerificationCheck {
  if (validFrom) {
    const from = new Date(validFrom);
    if (isNaN(from.getTime())) {
      return { name: "date", passed: false, detail: "Invalid validFrom date" };
    }
    if (now < from) {
      return {
        name: "date",
        passed: false,
        detail: `Credential not yet valid (validFrom: ${validFrom})`,
      };
    }
  }

  if (validUntil) {
    const until = new Date(validUntil);
    if (isNaN(until.getTime())) {
      return { name: "date", passed: false, detail: "Invalid validUntil date" };
    }
    if (now > until) {
      return {
        name: "date",
        passed: false,
        detail: `Credential expired (validUntil: ${validUntil})`,
      };
    }
  }

  return { name: "date", passed: true };
}

/**
 * Check revocation status via DeDi registry.
 *
 * The hash used for the DeDi query is preferentially extracted from
 * `credential.credentialStatus.id` (the hash the issuer committed to at
 * signing time) and falls back to a JCS-canonical SHA-256 of the whole
 * credential for credentials issued by other implementations. See
 * `resolveRevocationHash` in `@opencred/crypto` for the full contract —
 * issuance, verification, and revocation-submit MUST all agree on this hash
 * or revocation is silently broken.
 */
export async function checkRevocation(
  credential: unknown,
  dediClient: DeDiClient,
): Promise<VerificationCheck> {
  try {
    const hash = resolveRevocationHash(credential);
    const record = await dediClient.queryRevocationHash(hash);
    if (record.revoked) {
      const at = record.revokedAt ? ` at ${record.revokedAt}` : "";
      // Surface the issuer-supplied revocation reason when present so the
      // verifier can see *why* a credential was revoked. The reason is
      // already plumbed end-to-end at the data layer
      // (`RevocationHashRecord.reason`, populated from `details.reason`); it
      // was previously dropped here. When no reason is supplied the detail is
      // unchanged.
      const detail = record.reason
        ? `Credential revoked${at}. Reason: ${record.reason}.`
        : `Credential revoked${at}`;
      return { name: "revocation", passed: false, detail };
    }
    return { name: "revocation", passed: true };
  } catch {
    return {
      name: "revocation",
      passed: false,
      detail: "Unable to check revocation status: DeDi service unavailable",
    };
  }
}

// --- SSRF prevention for status list URL validation ---
//
// `isPrivateIP` is imported from @opencred/shared (the canonical SSRF helper).
// The canonical helper validates its input via `node:net`'s `isIP()`, so it
// expects bare IP literals (no surrounding brackets). Callers below strip
// brackets from IPv6 hostnames before delegating to it.

/** Known private/loopback hostnames. */
const PRIVATE_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "[::1]",
]);

/**
 * Validate a status list URL against SSRF rules.
 * - Must be a valid URL.
 * - Must use the https: scheme.
 * - Hostname must not be a private IP or loopback name.
 * - Hostname must be on the allowlist (if one is provided).
 */
function validateStatusListUrl(
  raw: string,
  allowedDomains?: string[],
): { valid: true; url: string; hostname: string } | { valid: false; detail: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { valid: false, detail: "Invalid status list URL" };
  }

  if (parsed.protocol !== "https:") {
    return { valid: false, detail: "Status list URL must use HTTPS" };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (PRIVATE_HOSTNAMES.has(hostname)) {
    return { valid: false, detail: "Status list URL points to a private/loopback host" };
  }

  // Check if hostname is a raw IP literal (IPv4 or bracketed IPv6).
  // URL.hostname returns bracketed IPv6 (e.g. "[::1]"); canonical isPrivateIP
  // expects the bare literal, so we strip brackets before delegation.
  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const isIPv6 = hostname.startsWith("[") || hostname.includes(":");
  if (isIPv4 || isIPv6) {
    const bare = hostname.replace(/^\[|\]$/g, "");
    if (isPrivateIP(bare)) {
      return { valid: false, detail: "Status list URL points to a private/reserved IP" };
    }
  }

  if (allowedDomains && allowedDomains.length > 0) {
    const allowed = allowedDomains.some(
      (d) => hostname === d.toLowerCase() || hostname.endsWith(`.${d.toLowerCase()}`),
    );
    if (!allowed) {
      return { valid: false, detail: "Status list URL domain is not on the allowlist" };
    }
  }

  return { valid: true, url: parsed.toString(), hostname };
}

/**
 * Resolve a hostname to an IP and validate that none of the resolved IPs are private.
 * Prevents DNS rebinding attacks by pinning the resolved IP for use in the fetch.
 */
export async function resolveAndValidateIp(
  hostname: string,
): Promise<{ address: string; family: 4 | 6 }> {
  let addresses: string[] = [];
  let family: 4 | 6 = 4;

  try {
    addresses = await resolve4(hostname);
  } catch {
    // resolve4 failed, try IPv6
  }

  if (addresses.length === 0) {
    try {
      addresses = await resolve6(hostname);
      family = 6;
    } catch {
      throw new Error(`DNS resolution failed for ${hostname}`);
    }
  }

  if (addresses.length === 0) {
    throw new Error(`DNS resolution failed for ${hostname}`);
  }

  // Validate ALL resolved IPs — if any are private, reject
  for (const addr of addresses) {
    if (isPrivateIP(addr)) {
      throw new Error(`DNS resolved to private/reserved IP for ${hostname}`);
    }
  }

  return { address: addresses[0], family };
}

/** Options for the BitstringStatusList check. */
export interface BitstringStatusListOptions {
  /** Optional allowlist of permitted domains for status list URLs. */
  allowedDomains?: string[];
  /** Optional DID resolver for verifying the proof on the status list credential. */
  didResolver?: DIDResolver;
}

/**
 * Check BitstringStatusList when credentialStatus.type is BitstringStatusListEntry.
 * Fetches the status list and checks the bit at the given index.
 *
 * Security measures:
 * - SSRF: Validates URL scheme (HTTPS only), blocks private IPs and loopback, supports domain allowlist.
 * - DNS rebinding: Resolves hostname and pins IP before fetch; validates resolved IPs against private ranges.
 * - Decompression bomb: Rejects compressed data larger than MAX_COMPRESSED_SIZE (1 MB).
 * - Event loop blocking: Uses async gunzip instead of gunzipSync.
 * - Proof verification: Optionally verifies the proof on the fetched status list credential.
 */
export async function checkBitstringStatusList(
  credentialStatus: Record<string, unknown>,
  options: BitstringStatusListOptions = {},
): Promise<VerificationCheck> {
  try {
    const statusListIndex = credentialStatus["statusListIndex"];
    const statusListCredential = credentialStatus["statusListCredential"];

    if (statusListIndex === undefined || statusListCredential === undefined) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Missing statusListIndex or statusListCredential in credentialStatus",
      };
    }

    const index = Number(statusListIndex);
    if (!Number.isInteger(index) || index < 0) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Invalid statusListIndex: ${String(statusListIndex)}`,
      };
    }

    // #123: Validate URL to prevent SSRF
    const urlValidation = validateStatusListUrl(
      String(statusListCredential),
      options.allowedDomains,
    );
    if (!urlValidation.valid) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: urlValidation.detail,
      };
    }

    // DNS rebinding prevention: resolve the hostname, validate the IP, and
    // PIN the connection to that validated address (fetchWithPinnedIp). The
    // URL keeps the original hostname so TLS SNI + certificate validation
    // still run against it — the previous approach of putting the IP in the
    // URL and sending a `Host` header fails certificate validation
    // (ERR_TLS_CERT_ALTNAME_INVALID), since certs are issued for hostnames,
    // not IPs.
    const parsedUrl = new URL(urlValidation.url);
    const hostname = parsedUrl.hostname;

    let pinnedAddresses: string[];
    if (isIP(hostname)) {
      // Literal-IP URL: already validated as public by validateStatusListUrl,
      // and with no DNS involved there is nothing to rebind.
      pinnedAddresses = [hostname];
    } else {
      const resolved = await resolveAndValidateIp(hostname);
      pinnedAddresses = [resolved.address];
    }

    // #469 (P1-02): the status-list fetch used to have no timeout, so a stalled
    // remote host could hold a verify request open indefinitely. Cap at 10 s
    // to match the DID-web resolver and DeDi client, which use the same
    // budget. AbortController + try/finally clearTimeout avoids a dangling
    // timer if fetch resolves first.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    let statusListVC: Record<string, unknown>;
    try {
      const response = await fetchWithPinnedIp(urlValidation.url, pinnedAddresses, {
        signal: controller.signal,
      });
      if (!response.ok) {
        return {
          name: "bitstringStatus",
          passed: false,
          detail: `Failed to fetch status list: HTTP ${response.status}`,
        };
      }

      statusListVC = (await response.json()) as Record<string, unknown>;
    } finally {
      clearTimeout(timer);
    }

    // #128: Verify proof on the status list credential before trusting it
    if (options.didResolver) {
      const proofCheck = await verifyDataIntegrity(
        statusListVC as unknown as VerifiableCredential,
        options.didResolver,
      );
      if (!proofCheck.passed) {
        return {
          name: "bitstringStatus",
          passed: false,
          detail: `Status list credential proof invalid: ${proofCheck.detail ?? "verification failed"}`,
        };
      }
    }

    const subject = statusListVC["credentialSubject"] as Record<string, unknown> | undefined;
    if (!subject) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Status list credential missing credentialSubject",
      };
    }

    const encodedList = subject["encodedList"] as string | undefined;
    if (!encodedList) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Status list credential missing encodedList",
      };
    }

    // Decode the base64-encoded, GZIP-compressed bitstring
    const compressed = Buffer.from(encodedList, "base64");

    // #127: Reject compressed data exceeding size limit to prevent decompression bombs
    if (compressed.length > MAX_COMPRESSED_SIZE) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Compressed encodedList exceeds maximum size (${MAX_COMPRESSED_SIZE} bytes)`,
      };
    }

    // #126: Use async gunzip instead of blocking gunzipSync
    const bitstring = await gunzip(compressed);

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    if (byteIndex >= bitstring.length) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `statusListIndex ${index} out of range`,
      };
    }

    // Bits are MSB-first within each byte
    const isRevoked = (bitstring[byteIndex] & (0x80 >> bitIndex)) !== 0;

    if (isRevoked) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Credential revoked (statusListIndex: ${index})`,
      };
    }

    return { name: "bitstringStatus", passed: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unable to check BitstringStatusList";
    return {
      name: "bitstringStatus",
      passed: false,
      detail: message,
    };
  }
}

// Export for testing
export { validateStatusListUrl as _validateStatusListUrl, MAX_COMPRESSED_SIZE };

// ---------------------------------------------------------------------------
// Key-status check (per-key registry: active / rotated / revoked)
// ---------------------------------------------------------------------------
//
// This check CAN flip the headline result. A signing key whose
// `opencred-key-registry` status is `revoked` means every credential it
// signed is rejected (top-level `REVOKED`) — a compromised key's signatures
// can't be trusted regardless of when they were produced. `active` and
// `rotated` both pass: a clean rotation leaves old credentials valid (there
// is nothing to invalidate). When the key's namespace can't be determined
// (a did:key credential with no `credentialStatus`), or DeDi has no record /
// is unreachable, the check degrades to a non-failing "not checked" — the
// credential stays VALID on the strength of its signature. There is no
// separate issuer-attribution check: the bare DID is the attribution, and
// the verifier UI surfaces it directly to the user.

/** Extract a string issuer DID from a credential's `issuer` field. */
function extractIssuerDid(credential: unknown): string | undefined {
  if (typeof credential !== "object" || credential === null) return undefined;
  const issuer = (credential as Record<string, unknown>)["issuer"];
  if (typeof issuer === "string") return issuer;
  if (typeof issuer === "object" && issuer !== null) {
    const id = (issuer as Record<string, unknown>)["id"];
    if (typeof id === "string") return id;
  }
  return undefined;
}

/**
 * Extract the signing key's verification method (the precise key id) from a
 * credential.
 *
 * Prefers the embedded proof's `verificationMethod` — present on
 * Data-Integrity and JWS-proof credentials, and the most reliable answer
 * because it names the exact key that signed *this* credential. Falls back
 * to deriving the conventional did:key verification method from the issuer
 * DID (the fragment equals the method-specific id) for credentials whose
 * proof we don't have in object form.
 */
function extractVerificationMethod(credential: unknown, issuerDid?: string): string | undefined {
  if (typeof credential === "object" && credential !== null) {
    const proof = (credential as Record<string, unknown>)["proof"];
    const proofObj = Array.isArray(proof) ? proof[0] : proof;
    if (proofObj != null && typeof proofObj === "object") {
      const vm = (proofObj as Record<string, unknown>)["verificationMethod"];
      if (typeof vm === "string" && vm.length > 0) return vm;
    }
  }
  if (issuerDid && issuerDid.startsWith("did:key:")) {
    const methodSpecificId = issuerDid.slice("did:key:".length);
    return `${issuerDid}#${methodSpecificId}`;
  }
  return undefined;
}

/**
 * Derive the DeDi namespace (the issuer's verified domain) for a key lookup,
 * so a verifier never needs to be pre-wired with the issuer's namespace.
 *
 * - **did:web** — the verified domain is the DID itself: `did:web:acme.com`
 *   → `acme.com`, `did:web:acme.com:eu:issuers` → `acme.com`.
 * - **otherwise** (did:key etc.) — the namespace travels in
 *   `credentialStatus.id`, whose path is
 *   `…/dedi/lookup/{namespace}/vc-revocation-registry/{hash}`.
 *
 * Returns `undefined` when no namespace can be determined — the caller then
 * degrades the key-status check to "not checked" rather than failing.
 */
function deriveKeyNamespace(credential: unknown, issuerDid?: string): string | undefined {
  if (issuerDid && issuerDid.startsWith("did:web:")) {
    const rest = issuerDid.slice("did:web:".length);
    const host = rest.split(":")[0]?.replace(/%3A/gi, ":");
    if (host) return host;
  }
  return extractNamespaceFromStatusId(credential);
}

/** Pull the `{namespace}` segment out of a `credentialStatus.id` lookup URL. */
function extractNamespaceFromStatusId(credential: unknown): string | undefined {
  if (typeof credential !== "object" || credential === null) return undefined;
  const status = (credential as Record<string, unknown>)["credentialStatus"];
  if (typeof status !== "object" || status === null) return undefined;
  const rawId = (status as Record<string, unknown>)["id"];
  if (typeof rawId !== "string" || rawId.length === 0) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(rawId);
  } catch {
    return undefined;
  }
  const segments = parsed.pathname.split("/").filter((s) => s.length > 0);
  const lookupIdx = segments.indexOf("lookup");
  if (lookupIdx >= 0 && lookupIdx + 1 < segments.length) {
    return segments[lookupIdx + 1];
  }
  return undefined;
}

/**
 * Check the signing key's lifecycle status in the `opencred-key-registry`.
 *
 * - `revoked` → **fail** (`passed: false`); the verifier maps this to a
 *   top-level `REVOKED`. The credential is rejected because a revoked key
 *   may be compromised.
 * - `rotated` / `active` → pass. A rotated key is a *clean* retirement, so
 *   credentials signed by it remain valid.
 * - no namespace / no record (404) / DeDi outage → pass with a "not checked"
 *   detail. The credential stays VALID; key status is simply not consulted.
 *
 * Applies to all DID methods. Requires a configured `dediClient`; with no
 * client the check is a silent pass (status can't be consulted).
 */
export async function checkKeyStatus(
  credential: unknown,
  dediClient?: DeDiClient,
): Promise<VerificationCheck> {
  if (!dediClient) {
    return { name: "keyStatus", passed: true };
  }
  const issuerDid = extractIssuerDid(credential);
  const verificationMethod = extractVerificationMethod(credential, issuerDid);
  if (!verificationMethod) {
    return {
      name: "keyStatus",
      passed: true,
      detail: "Key status not checked: no verification method on the credential",
    };
  }
  const namespace = deriveKeyNamespace(credential, issuerDid);
  try {
    const record = await dediClient.resolveKey(verificationMethod, namespace);
    if (record.status === "revoked") {
      return {
        name: "keyStatus",
        passed: false,
        detail:
          "Signing key has been revoked. The credential is rejected because a revoked key may be compromised.",
      };
    }
    if (record.status === "rotated") {
      return {
        name: "keyStatus",
        passed: true,
        detail: "Signing key was cleanly rotated; the credential remains valid.",
      };
    }
    return { name: "keyStatus", passed: true };
  } catch (err) {
    // Defensive degrade — never fail verification because DeDi couldn't
    // answer. 404 = no record for this key; 400 = no namespace determinable
    // (resolveNamespace threw); anything else = transient outage. All stay
    // VALID with a "not checked / unknown" note.
    const code = err instanceof DeDiClientError ? err.statusCode : 0;
    if (code === 404) {
      return {
        name: "keyStatus",
        passed: true,
        detail: "Key status not checked: no registry record for this key",
      };
    }
    if (code === 400) {
      return {
        name: "keyStatus",
        passed: true,
        detail: "Key status not checked: issuer namespace could not be determined",
      };
    }
    const message =
      err instanceof Error && err.message ? err.message : "DeDi key-status lookup failed";
    return { name: "keyStatus", passed: true, detail: `Key status unknown: ${message}` };
  }
}

// ---------------------------------------------------------------------------
// Registry anchor check (CORD-via-DeDi advisory)
// ---------------------------------------------------------------------------
//
// Advisory: surfaces the DeDi `proof` block returned alongside the key record
// so verifier UIs can show "anchored on CORD by ..." provenance. Does NOT
// flip the headline `verified` boolean — the underlying VC signature is the
// authority on cryptographic validity. The check communicates two things:
//
//   1. Whether DeDi attached an on-chain anchor proof to the key record
//      (presence is informative; absence is benign on networks that don't
//      anchor).
//   2. Whether the proof's `creator_did` matches the credential's issuer DID
//      (a mismatch is suspicious — DeDi is reporting the record was anchored
//      by someone other than the issuer the credential is signed by).
//
// On-chain CORD verification (looking up the digest in a CORD block) is out
// of scope for this first cut. We only surface the proof metadata the DeDi
// instance hands us. A compromised DeDi could fabricate a proof block; that's
// what a follow-up on-chain check would harden against.

/** Truncate a long hex/string value for display in check details. */
function abbrev(value: string, head = 12, tail = 6): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/**
 * Check the DeDi-surfaced CORD anchor proof on the signing key's record.
 *
 * Scope: meaningful whenever a key record can be resolved (any DID method)
 * and a `dediClient` is configured. Passes silently when the concept doesn't
 * apply (no client, no verification method, no record) so unrelated
 * credentials don't carry a noisy check.
 *
 * Outcomes:
 * - Record with a well-formed proof whose `creator_did` matches the issuer
 *   DID → pass; detail surfaces "Anchored on CORD by {did}".
 * - Record with no proof block → pass: false (advisory) so the UI can
 *   surface "no anchor info" without rejecting the credential.
 * - Proof present but `creator_did` mismatch → pass: false with a suspicion
 *   note; verifier policy can treat that as a reason to reject.
 * - 404 / no namespace / outage → pass with an "anchor status unknown"
 *   detail (a DeDi hiccup must never block a cryptographically valid VC).
 */
export async function checkRegistryAnchor(
  credential: unknown,
  dediClient?: DeDiClient,
): Promise<VerificationCheck> {
  if (!dediClient) {
    return { name: "registryAnchor", passed: true };
  }
  const issuerDid = extractIssuerDid(credential);
  const verificationMethod = extractVerificationMethod(credential, issuerDid);
  if (!verificationMethod) {
    return { name: "registryAnchor", passed: true };
  }
  const namespace = deriveKeyNamespace(credential, issuerDid);
  try {
    const record = await dediClient.resolveKey(verificationMethod, namespace);
    const proof = record.proof;
    if (!proof) {
      return {
        name: "registryAnchor",
        passed: false,
        detail:
          "Signing key record was found in DeDi but has no CORD anchor proof. Cannot confirm on-chain publication.",
      };
    }
    if (issuerDid && proof.creator_did !== issuerDid) {
      return {
        name: "registryAnchor",
        passed: false,
        detail: `CORD anchor creator (${proof.creator_did}) does not match issuer DID (${issuerDid}). The registry record was published by a different party than the credential's issuer.`,
      };
    }
    const networkSuffix = proof.network_genesis
      ? ` on network ${abbrev(proof.network_genesis)}`
      : "";
    return {
      name: "registryAnchor",
      passed: true,
      detail: `Anchored on CORD${networkSuffix} by ${proof.creator_did} (digest ${abbrev(proof.digest)}).`,
    };
  } catch (err) {
    const code = err instanceof DeDiClientError ? err.statusCode : 0;
    if (code === 404 || code === 400) {
      return { name: "registryAnchor", passed: true };
    }
    const message = err instanceof Error && err.message ? err.message : "DeDi anchor lookup failed";
    return {
      name: "registryAnchor",
      passed: true,
      detail: `Anchor status unknown: ${message}`,
    };
  }
}
