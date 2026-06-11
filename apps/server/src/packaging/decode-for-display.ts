/**
 * Decode a compact-token credential (`vc-jwt` or `sd-jwt-vc`) for offline
 * packaging.
 *
 * **This module performs no signature verification.** It only parses the
 * encoded payload so the packager can render display fields (subject name,
 * issuer label, validity dates, etc.) into a PDF certificate or extract
 * `id` / `type` for filename generation. The integrity guarantee comes
 * from the signed compact token itself, which we embed verbatim into the
 * QR code so any verifier scanning the QR runs a real cryptographic check.
 *
 * Two input shapes are supported:
 *
 *   1. **vc-jwt** — three base64url segments separated by `.`, payload is
 *      a JWT carrying either the W3C VC-JWT 1.1 `vc` claim or the 2.0 flat
 *      layout. We delegate the layout-aware extraction to
 *      `extractVcJwtCredentialFields` from `@opencred/verification`.
 *
 *   2. **sd-jwt-vc** — issuer JWT followed by `~`-separated disclosures.
 *      The disclosures must travel with the credential (the QR embeds the
 *      whole thing); for *display purposes* we re-attach any disclosed
 *      claims so the PDF shows real values. We also recursively strip
 *      `_sd` / `_sd_alg` markers at every nesting level so they don't
 *      appear as raw hash arrays in the rendered certificate.
 *
 *      **Limitation:** disclosures whose hashes appear in *nested* `_sd`
 *      arrays are not re-merged — only the top-level disclosure→claim
 *      mapping is honoured. Nested withheld claims simply don't appear,
 *      which is the desired behaviour from a privacy perspective. (Spec:
 *      draft-ietf-oauth-selective-disclosure-jwt §4.2.4.) If a future
 *      issuer pattern requires nested re-merging, extend
 *      `attachDisclosures` to walk the tree.
 *
 * Returns a synthetic VC-shaped record suitable for the existing PDF /
 * JSON-export code paths, plus the original compact token (so the QR
 * generator can embed it verbatim). The shape is **not** a fully-formed
 * W3C VerifiableCredential — its `proof` block is a *display-only*
 * placeholder built from JWT header/payload claims, never used for
 * cryptographic verification. See `buildVcShape` for the field
 * derivations.
 */

import {
  extractVcJwtCredentialFields,
  decodeJwtPayloadUnsafe,
  decodeDisclosure as decodeDisclosureFromVerification,
  type VcJwtPayload,
} from "@opencred/verification";
import { ValidationError } from "@opencred/shared";
import { getLogger } from "../logger.js";

/** Compact-token-aware shape returned to the packager. */
export interface DecodedForDisplay {
  /**
   * Synthetic VC-shaped object reconstructed from the token payload. Has
   * at least `id`, `type`, `issuer`, `credentialSubject`, a synthetic
   * `proof` block, and (best-effort) `validFrom` / `validUntil`.
   *
   * **Display-only.** The synthetic `proof` block carries `{ type,
   * created, verificationMethod }` derived from the JWT header/payload
   * — it is *not* a Data Integrity proof, and downstream code must never
   * use it to gate verification. The real cryptographic integrity lives
   * in `compactToken`.
   */
  vcShape: Record<string, unknown>;
  /**
   * The original compact token, intact. Embedded into QR codes so a
   * scanner can run real signature verification against the issuer's
   * public key. Never mutated.
   */
  compactToken: string;
  /** Which encoding the original token used. */
  format: "vc-jwt" | "sd-jwt-vc";
}

/**
 * Decode an SD-JWT disclosure into a [name, value] tuple, or return
 * `null` for non-name (array-element) disclosures, which the display
 * layer cannot use. Errors are swallowed — a malformed disclosure
 * shouldn't fail the entire packaging operation; the field stays hidden
 * in the rendered PDF — but we emit a `debug`-level log so operators
 * can opt into investigation via `OPENCRED_LOG_LEVEL=debug`.
 */
function decodeDisclosureForDisplay(d: string, index: number): [string, unknown] | null {
  try {
    const decoded = decodeDisclosureFromVerification(d);
    // decodeDisclosure returns either [salt, name, value] (length 3) or
    // [salt, value] (length 2 — array-element disclosure). We can only
    // surface name/value pairs in the PDF.
    if (decoded.length === 3) {
      return [decoded[1], decoded[2]];
    }
    getLogger().debug(
      { index },
      "SD-JWT array-element disclosure ignored for PDF render (no claim name)",
    );
    return null;
  } catch (err) {
    getLogger().debug(
      { index, err: err instanceof Error ? err.message : String(err) },
      "SD-JWT disclosure decode failed; field will not appear in PDF",
    );
    return null;
  }
}

/**
 * Recursively strip `_sd` and `_sd_alg` markers from an object tree so
 * they don't surface in the rendered PDF as raw hash arrays.
 *
 * SD-JWT spec (draft-ietf-oauth-selective-disclosure-jwt §4.2.4) allows
 * `_sd` to appear at any object nesting level. The PDF subject-rendering
 * loop walks `credentialSubject` and prints every key/value pair, so a
 * survived `_sd` marker would show up as `Sd: <hash array>` on the
 * certificate. We strip every level.
 *
 * Returns a fresh tree (input is not mutated). Arrays are walked but
 * left otherwise intact.
 */
function stripSdMarkers(input: unknown): unknown {
  if (Array.isArray(input)) {
    return input.map(stripSdMarkers);
  }
  if (input !== null && typeof input === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (k === "_sd" || k === "_sd_alg") continue;
      out[k] = stripSdMarkers(v);
    }
    return out;
  }
  return input;
}

/**
 * Re-attach disclosed claims to the SD-JWT payload so the PDF shows
 * human-readable values instead of `_sd` hash placeholders.
 *
 * **Top-level only**: we merge name/value disclosures into the top-level
 * payload and recursively strip `_sd` / `_sd_alg` markers at every
 * level. Nested disclosure re-merging (i.e. matching a nested `_sd`
 * digest with its disclosure) is intentionally not implemented — those
 * claims simply remain hidden, which matches the holder's privacy
 * intent. See module JSDoc for the spec reference.
 *
 * Disclosure→payload key collisions are dropped (existing payload field
 * wins) — this prevents a malicious holder from forging values for
 * already-published claims like `iss` or `sub`. We log every collision
 * at `debug` for audit visibility.
 */
function attachDisclosures(
  payload: Record<string, unknown>,
  disclosures: string[],
): Record<string, unknown> {
  const stripped = stripSdMarkers(payload) as Record<string, unknown>;
  const merged: Record<string, unknown> = { ...stripped };
  disclosures.forEach((d, index) => {
    const decoded = decodeDisclosureForDisplay(d, index);
    if (!decoded) return;
    const [name, value] = decoded;
    if (name in merged) {
      getLogger().debug(
        { name, index },
        "SD-JWT disclosure name collides with existing payload claim — original kept",
      );
      return;
    }
    merged[name] = value;
  });
  return merged;
}

/**
 * Try to extract the `kid` (key id) from a JWT's protected header — used
 * to populate `proof.verificationMethod` in the synthetic display block.
 * Returns `undefined` if the header is missing, malformed, or has no
 * `kid` claim. Never throws.
 *
 * Header is the first dot-separated segment of a JWS / JWT.
 */
function extractKidFromJwtHeader(token: string): string | undefined {
  return extractStringFromJwtHeader(token, "kid");
}

/** Like {@link extractKidFromJwtHeader} but for the JWS `alg` (display only). */
function extractAlgFromJwtHeader(token: string): string | undefined {
  return extractStringFromJwtHeader(token, "alg");
}

function extractStringFromJwtHeader(token: string, claim: string): string | undefined {
  try {
    const headerSeg = token.split(".")[0] ?? "";
    if (!headerSeg) return undefined;
    const decoded: unknown = JSON.parse(Buffer.from(headerSeg, "base64url").toString("utf-8"));
    if (
      decoded &&
      typeof decoded === "object" &&
      typeof (decoded as Record<string, unknown>)[claim] === "string"
    ) {
      return (decoded as Record<string, unknown>)[claim] as string;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * The set of JWT/SD-JWT registered claims that should *not* be promoted
 * into a synthetic `credentialSubject`.
 *
 * Sourced from RFC 7519 §4.1 (the `iss/sub/aud/exp/nbf/iat/jti` standard
 * set), draft-ietf-oauth-sd-jwt-vc (`vct` for credential-type), and the
 * SD-JWT framing claims (`_sd`, `_sd_alg`, `cnf` from RFC 7800 holder
 * binding, `status` from various draft status mechanisms).
 *
 * **Maintenance warning:** if a new SD-JWT registered claim is added by
 * the spec, append it here. A claim missing from this set will leak
 * into the rendered `credentialSubject` and appear as a fake field on
 * the certificate (e.g. `Status: { uri: ... }`).
 */
const RESERVED_JWT_CLAIMS = new Set([
  "iss",
  "sub",
  "aud",
  "exp",
  "nbf",
  "iat",
  "jti",
  "vct",
  "cnf",
  "_sd",
  "_sd_alg",
  "status",
]);

/**
 * Build a synthetic VC shape that the existing PDF / JSON layouts can
 * consume. `id`, `type`, `issuer`, `credentialSubject`, and a synthetic
 * `proof` block are always populated; `validFrom` / `validUntil` are
 * filled when the source has them. See `DecodedForDisplay.vcShape`
 * JSDoc for the display-only contract.
 */
function buildVcShape(
  source: Record<string, unknown>,
  format: "vc-jwt" | "sd-jwt-vc",
  compactToken: string,
  fallbackIssuer?: string,
  validFrom?: string,
  validUntil?: string,
): Record<string, unknown> {
  const shape: Record<string, unknown> = { ...source };

  if (!shape["id"]) {
    // Use the JWT-level `jti` if present, else a synthetic placeholder so
    // the PDF "ID:" line and filename slug have something to render. This
    // is purely cosmetic — the real cryptographic id lives in the token.
    shape["id"] = (source["jti"] as string | undefined) ?? "urn:opencred:packaged-token";
  }
  if (!shape["type"]) {
    // Fall back to `vct` (sd-jwt-vc) before defaulting.
    const vct = source["vct"] as string | undefined;
    shape["type"] = vct ? ["VerifiableCredential", vct] : ["VerifiableCredential"];
  }
  if (!shape["issuer"] && fallbackIssuer) {
    shape["issuer"] = fallbackIssuer;
  }
  if (!shape["credentialSubject"]) {
    // sd-jwt-vc payloads put subject claims at the top level alongside
    // `iss`/`iat`/etc. Promote every non-reserved top-level claim into
    // a synthetic `credentialSubject` so the PDF subject loop has fields
    // to render. This includes nested objects and arrays — the PDF
    // layout already handles those.
    const subject: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(source)) {
      if (!RESERVED_JWT_CLAIMS.has(k)) {
        subject[k] = v;
      }
    }
    if (typeof source["sub"] === "string") {
      subject["id"] = source["sub"];
    }
    shape["credentialSubject"] = subject;
  }
  if (validFrom && !shape["validFrom"]) shape["validFrom"] = validFrom;
  if (validUntil && !shape["validUntil"]) shape["validUntil"] = validUntil;

  // Synthesize a *display-only* `proof` block so the PDF's "Digital
  // Signature" section has meaningful content. Format-aware: vc-jwt uses
  // the `JsonWebSignature2020` cryptosuite type recognised by the W3C
  // VC-JWT spec; sd-jwt-vc isn't a Data Integrity proof at all, so we
  // surface the SD-JWT-VC media type instead. Neither value is used for
  // cryptographic verification — that always runs against `compactToken`.
  if (!shape["proof"]) {
    const proofBlock: Record<string, unknown> = {
      type: format === "vc-jwt" ? "JsonWebSignature2020" : "SD-JWT-VC",
    };
    if (typeof source["iat"] === "number") {
      try {
        proofBlock["created"] = new Date(source["iat"] * 1000).toISOString();
      } catch {
        // RangeError for non-finite or out-of-range iat; just skip the field.
      }
    }
    const kid = extractKidFromJwtHeader(compactToken);
    if (kid) proofBlock["verificationMethod"] = kid;
    const alg = extractAlgFromJwtHeader(compactToken);
    if (alg) proofBlock["algorithm"] = alg;
    shape["proof"] = proofBlock;
  }
  return shape;
}

/**
 * Decode a compact-token credential for display. Throws
 * `ValidationError` if the input doesn't look like a compact JWT or
 * SD-JWT-VC token.
 */
export function decodeCompactCredentialForDisplay(token: string): DecodedForDisplay {
  if (typeof token !== "string" || token.length === 0) {
    throw new ValidationError("Compact credential token is empty");
  }

  // SD-JWT-VC: <issuer-jwt>~<disclosure>~<disclosure>~ ...  (optional trailing `~`)
  if (token.includes("~")) {
    const segments = token.split("~");
    const issuerJwt = segments[0];
    // Remaining segments are disclosures + an optional empty trailing
    // segment (when the producer terminates with `~`). Drop empties.
    const disclosures = segments.slice(1).filter((s) => s.length > 0);

    let payload: Record<string, unknown>;
    try {
      payload = decodeJwtPayloadUnsafe(issuerJwt);
    } catch (err) {
      throw new ValidationError(
        `Invalid sd-jwt-vc compact token: cannot decode issuer JWT (${
          err instanceof Error ? err.message : "unknown error"
        })`,
      );
    }

    const merged = attachDisclosures(payload, disclosures);
    const validFrom =
      typeof merged["nbf"] === "number" ? new Date(merged["nbf"] * 1000).toISOString() : undefined;
    const validUntil =
      typeof merged["exp"] === "number" ? new Date(merged["exp"] * 1000).toISOString() : undefined;

    return {
      vcShape: buildVcShape(
        merged,
        "sd-jwt-vc",
        token,
        merged["iss"] as string | undefined,
        validFrom,
        validUntil,
      ),
      compactToken: token,
      format: "sd-jwt-vc",
    };
  }

  // VC-JWT: <header>.<payload>.<signature> — exactly two `.`s.
  const dotCount = (token.match(/\./g) ?? []).length;
  if (dotCount !== 2) {
    throw new ValidationError(
      `Compact credential token does not look like a JWT (expected 2 '.' separators, got ${dotCount})`,
    );
  }

  let payload: VcJwtPayload;
  try {
    payload = decodeJwtPayloadUnsafe(token) as VcJwtPayload;
  } catch (err) {
    throw new ValidationError(
      `Invalid vc-jwt compact token: cannot decode payload (${
        err instanceof Error ? err.message : "unknown error"
      })`,
    );
  }

  // Layout-aware extraction (handles both DM 1.1 nested-`vc` and DM 2.0 flat).
  const fields = extractVcJwtCredentialFields(payload);
  const source = fields.credential ?? (payload as unknown as Record<string, unknown>);

  return {
    vcShape: buildVcShape(
      source,
      "vc-jwt",
      token,
      fields.issuer,
      fields.validFrom,
      fields.validUntil,
    ),
    compactToken: token,
    format: "vc-jwt",
  };
}
