import { resolve4, resolve6 } from "node:dns/promises";
import { isIP } from "node:net";
import { promisify } from "node:util";
import { gunzip as gunzipCb } from "node:zlib";
import type { DeDiClient } from "@opencred/dedi-client";
import { resolveRevocationHash } from "@opencred/crypto";
import type { DIDResolver } from "@opencred/did";
import { isPrivateIP } from "@opencred/shared";
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
      return {
        name: "revocation",
        passed: false,
        detail: `Credential revoked${record.revokedAt ? ` at ${record.revokedAt}` : ""}`,
      };
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

    // DNS rebinding prevention: resolve hostname and pin IP before fetch
    let fetchUrl = urlValidation.url;
    const fetchHeaders: Record<string, string> = {};

    const parsedUrl = new URL(urlValidation.url);
    const hostname = parsedUrl.hostname;

    if (!isIP(hostname)) {
      const resolved = await resolveAndValidateIp(hostname);
      // Replace hostname with resolved IP; set Host header to original hostname
      const pinnedUrl = new URL(urlValidation.url);
      if (resolved.family === 6) {
        pinnedUrl.hostname = `[${resolved.address}]`;
      } else {
        pinnedUrl.hostname = resolved.address;
      }
      fetchUrl = pinnedUrl.toString();
      fetchHeaders["Host"] = hostname;
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
      const response = await globalThis.fetch(fetchUrl, {
        redirect: "error", // Prevent redirect-based SSRF
        headers: fetchHeaders,
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
// Issuer attribution + key supersession checks (did:key adoption)
// ---------------------------------------------------------------------------
//
// These two checks are advisory — they appear in `checks[]` so verifier UIs
// can distinguish "cryptographically valid" from "attributed to a trusted
// issuer", but they do NOT flip the headline `verified` boolean. That
// invariant is intentional: a did:web credential that resolved successfully
// is implicitly attributed by its domain, and a did:key credential that
// hasn't been registered to DeDi still has a valid signature. The verifier
// caller decides what trust level to require.

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
 * Verify that the credential's issuer is attributed to a known organisation.
 *
 * Semantics by DID method:
 *
 * - **did:web** — the domain itself is the attribution. We trust that the
 *   verifier's existing DID resolution succeeded (or it would have failed
 *   the signature check upstream). The attribution `source` is `"did:web"`
 *   and the detail carries the domain string.
 *
 * - **did:key + DeDi configured** — query the DeDi registry by DID. A hit
 *   reports `source: "dedi"` with the org name; a miss reports
 *   `passed: false` with `source: "none"` (non-blocking — the credential is
 *   still cryptographically valid, just unattributed).
 *
 * - **did:key + DeDi not configured** — passes with `passed: false` and
 *   `source: "none"` so the UI can show "unattributed". The verifier could
 *   layer a local trust list on top in a future iteration.
 *
 * - **Other DID methods or non-DID issuers** — passes with `passed: false`
 *   so unknown shapes don't get a spurious green checkmark.
 *
 * Failure modes (DeDi unreachable / record malformed) degrade to
 * `passed: false` with a descriptive detail rather than throwing — same
 * pattern as `checkRevocation`.
 */
export async function checkIssuerAttribution(
  credential: unknown,
  dediClient?: DeDiClient,
): Promise<VerificationCheck> {
  const did = extractIssuerDid(credential);
  if (!did) {
    return {
      name: "issuerAttribution",
      passed: false,
      detail: "Credential has no resolvable issuer DID",
    };
  }

  if (did.startsWith("did:web:")) {
    // The domain in the DID is the attribution. No DeDi call required;
    // resolution success upstream (signature check passed) means the domain
    // serves the published key.
    return {
      name: "issuerAttribution",
      passed: true,
      detail: `Attributed via did:web — ${did}`,
    };
  }

  if (did.startsWith("did:key:")) {
    if (!dediClient) {
      return {
        name: "issuerAttribution",
        passed: false,
        detail: "Unattributed did:key issuer (no DeDi registry configured)",
      };
    }
    try {
      const record = await dediClient.resolveDID(did);
      const orgName = record.metadata?.orgName;
      const verifiedDomain = record.metadata?.verifiedDomain;
      return {
        name: "issuerAttribution",
        passed: true,
        detail: verifiedDomain
          ? `Attributed via DeDi to ${orgName ?? did} (verified domain: ${verifiedDomain})`
          : orgName
            ? `Attributed via DeDi to ${orgName}`
            : `Registered in DeDi (no org metadata)`,
      };
    } catch (err) {
      // Distinguish "no record found" (expected for unregistered did:key)
      // from "DeDi unreachable" (operator-visible failure). Both surface as
      // passed:false, but with different details so the UI can render
      // "unattributed" vs "lookup failed" appropriately.
      const message =
        err instanceof Error && err.message ? err.message : "DeDi attribution lookup failed";
      return {
        name: "issuerAttribution",
        passed: false,
        detail: message.toLowerCase().includes("not found")
          ? "Unattributed did:key issuer (no DeDi record)"
          : `Unable to check attribution: ${message}`,
      };
    }
  }

  return {
    name: "issuerAttribution",
    passed: false,
    detail: `Cannot attribute issuer with unsupported DID method: ${did.split(":")[1] ?? "?"}`,
  };
}

/**
 * Check whether the credential's issuer key has been superseded by a
 * successor (e.g. the issuer rotated to a new did:key after compromise).
 *
 * Only meaningful for did:key issuers with DeDi configured — did:web does
 * its own rotation natively, and non-DID issuers have no successor concept.
 * For those cases this check is a no-op pass (so it never blocks a credential
 * that the supersession concept doesn't apply to).
 *
 * When DeDi reports a `supersededBy` record, this check fails with the
 * successor DID in the detail, letting the verifier UI surface a red
 * "issuer key superseded" badge. The headline `verified` boolean stays
 * driven by the signature check — the credential is still cryptographically
 * valid against the old key — but verifier policy can treat supersession
 * as a reason to reject.
 *
 * Times out fast and degrades to a pass on DeDi unreachability so a DeDi
 * outage doesn't block verification.
 */
export async function checkKeySupersession(
  credential: unknown,
  dediClient?: DeDiClient,
): Promise<VerificationCheck> {
  const did = extractIssuerDid(credential);
  if (!did || !did.startsWith("did:key:") || !dediClient) {
    return { name: "keySupersession", passed: true };
  }
  try {
    const record = await dediClient.resolveDID(did);
    if (record.supersededBy) {
      const successor = record.supersededBy;
      return {
        name: "keySupersession",
        passed: false,
        detail: `Issuer key superseded by ${successor.did} at ${successor.at}${
          successor.reason ? ` — ${successor.reason}` : ""
        }`,
      };
    }
    return { name: "keySupersession", passed: true };
  } catch (err) {
    // Same defensive degrade as attribution: don't fail verification just
    // because DeDi is down. The verifier UI can surface "unknown supersession
    // status" if it cares.
    const message =
      err instanceof Error && err.message ? err.message : "DeDi supersession lookup failed";
    if (message.toLowerCase().includes("not found")) {
      // No record means we have no supersession info; treat as "no successor".
      return { name: "keySupersession", passed: true };
    }
    return {
      name: "keySupersession",
      passed: true,
      detail: `Supersession status unknown: ${message}`,
    };
  }
}
