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
 *      whole thing); for *display purposes* we only decode the issuer JWT
 *      and re-attach any disclosed claims so the PDF shows real values
 *      instead of `_sd` hash placeholders. Selectively-withheld claims
 *      remain hidden — that's the whole point of selective disclosure.
 *
 * Returns a `VerifiableCredential`-shaped record suitable for the existing
 * PDF / JSON-export code paths, plus the original compact token (so the
 * QR generator can embed it verbatim). The returned object is **not** a
 * fully-formed VC — it has no `proof` block — but the packager already
 * tolerates missing `proof` (it never inspects it).
 */

import {
  extractVcJwtCredentialFields,
  decodeJwtPayloadUnsafe,
  decodeDisclosure as decodeDisclosureFromVerification,
  type VcJwtPayload,
} from "@opencred/verification";
import { ValidationError } from "@opencred/shared";

/** Compact-token-aware shape returned to the packager. */
export interface DecodedForDisplay {
  /**
   * VC-shaped object reconstructed from the token payload. Has at least
   * `id`, `type`, `issuer`, `credentialSubject`, and (best-effort)
   * `validFrom` / `validUntil`. No `proof` field — the integrity
   * guarantee lives in the original compact token, not this synthetic
   * object.
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
 * layer cannot use. Errors are swallowed: a malformed disclosure
 * shouldn't fail the entire packaging operation; the field just stays
 * hidden in the rendered PDF.
 */
function decodeDisclosureForDisplay(d: string): [string, unknown] | null {
  try {
    const decoded = decodeDisclosureFromVerification(d);
    // decodeDisclosure returns either [salt, name, value] (length 3) or
    // [salt, value] (length 2 — array-element disclosure). We can only
    // surface name/value pairs in the PDF.
    if (decoded.length === 3) {
      return [decoded[1], decoded[2]];
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Re-attach disclosed claims to the SD-JWT payload so the PDF shows
 * human-readable values instead of `_sd` hashes.
 *
 * This is intentionally non-recursive and best-effort: we strip the
 * top-level `_sd` array (which lists *hashes* of all disclosable claims)
 * and merge each successfully-decoded disclosure as a top-level field.
 * Selectively-withheld claims (whose disclosures aren't present) stay
 * hidden — exactly what the holder intended when they redacted them.
 */
function attachDisclosures(
  payload: Record<string, unknown>,
  disclosures: string[],
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...payload };
  delete merged["_sd"];
  delete merged["_sd_alg"];
  for (const d of disclosures) {
    const decoded = decodeDisclosureForDisplay(d);
    if (decoded) {
      const [name, value] = decoded;
      // Don't clobber existing fields (the issuer may have published the
      // claim alongside its hash — though that's unusual).
      if (!(name in merged)) {
        merged[name] = value;
      }
    }
  }
  return merged;
}

/**
 * Build a synthetic VC shape that the existing PDF / JSON layouts can
 * consume. `id` and `type` are required by `getCredentialTitle()` and
 * `suggestedBaseName()`; supply safe defaults if the token didn't carry
 * them (older issuers may emit minimal payloads).
 */
function buildVcShape(
  source: Record<string, unknown>,
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
    // `iss`/`iat`/etc. The PDF layout walks `credentialSubject.*` to
    // render fields, so promote the non-JWT-standard claims into a
    // synthetic credentialSubject when there isn't one.
    const reservedJwtClaims = new Set([
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
    const subject: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(source)) {
      if (!reservedJwtClaims.has(k) && typeof v !== "object") {
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
  // Synthesize a `proof` block so PDF templates that render signature
  // metadata have something useful to show. The integrity guarantee
  // lives in the original JWT (embedded verbatim in the QR); this block
  // is *for display only* and is never written back into the credential
  // identity. `iat` (issued-at) is the closest analogue to `created`.
  if (!shape["proof"]) {
    const proofBlock: Record<string, unknown> = {
      type: "JsonWebSignature2020",
    };
    if (typeof source["iat"] === "number") {
      proofBlock["created"] = new Date(source["iat"] * 1000).toISOString();
    }
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
      vcShape: buildVcShape(merged, merged["iss"] as string | undefined, validFrom, validUntil),
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
    vcShape: buildVcShape(source, fields.issuer, fields.validFrom, fields.validUntil),
    compactToken: token,
    format: "vc-jwt",
  };
}
