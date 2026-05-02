/**
 * Credential packager — orchestrates offline packaging of signed VCs.
 *
 * Accepts a discriminated `CredentialInput` union — either a JSON-LD
 * `VerifiableCredential` (`{ kind: "vc", credential }`) or a compact
 * `vc-jwt` / `sd-jwt-vc` token (`{ kind: "compact-token", token }`). The
 * discriminator surfaces what `string` would otherwise hide: a string
 * here means a compact token, never a stringified VC. See
 * `./types.ts` for the rationale.
 *
 * **JWT input handling:** the compact token is decoded *for display*
 * only — no signature verification. The packager reconstructs a
 * VC-shaped object from the JWT payload to drive the PDF layout, and
 * embeds the original compact token verbatim in the QR code (so any
 * verifier scanning the QR runs a real cryptographic check). The JSON
 * export wraps the token in a small `{ format, credential }` envelope
 * to keep the file mime-typeable as `application/json`.
 */

import type { TemplateCustomization } from "@opencred/templates";
import { generateQrPng, generateQrSvg } from "./qr-generator.js";

// Re-export for use by verification and other consumers
export { decodeQrData } from "./qr-generator.js";
import { generatePdf } from "./pdf-generator.js";
import { exportAsJson, exportAsCompactJson } from "./json-export.js";
import { decodeCompactCredentialForDisplay } from "./decode-for-display.js";
import type { CredentialInput, PartialVerifiableCredential } from "./types.js";

// Re-export so downstream consumers (routes, tests) don't have to import
// from two different paths.
export type { CredentialInput, PartialVerifiableCredential } from "./types.js";

/**
 * Options for credential packaging.
 */
export interface PackagingOptions {
  /** Issuer branding customization (colors, logo, display name). */
  customization?: TemplateCustomization;
}

/**
 * Supported output formats for credential packaging.
 */
export type PackageFormat = "qr-png" | "qr-svg" | "pdf" | "json" | "json-compact";

/**
 * A single packaged output item.
 */
export interface PackagedOutput {
  format: PackageFormat;
  /** The output data — string for SVG/JSON, data URL for QR PNG, Buffer for PDF/QR buffer. */
  data: string | Buffer;
  /** MIME type of the output. */
  mimeType: string;
  /** Suggested file name for saving. */
  suggestedFileName: string;
}

/**
 * Result of a packaging operation.
 */
export interface PackagingResult {
  outputs: PackagedOutput[];
  errors: Array<{ format: PackageFormat; error: string }>;
}

/**
 * Generate a suggested file name base from a credential. Tolerant of
 * synthetic VC shapes (compact-token-derived) that may fall back to a
 * placeholder `id` like `urn:opencred:packaged-token` and a minimal
 * `type` array of just `["VerifiableCredential"]`.
 */
function suggestedBaseName(credential: PartialVerifiableCredential): string {
  const typeArr = Array.isArray(credential.type)
    ? credential.type
    : [String(credential.type ?? "")];
  const types = typeArr.filter((t) => t !== "VerifiableCredential");
  const typeSlug =
    types.length > 0
      ? types[0]
          .replace(/[^A-Za-z0-9]+/g, "-")
          .replace(/([a-z])([A-Z])/g, "$1-$2")
          .toLowerCase()
          .replace(/^-+|-+$/g, "")
      : "credential";
  const id = typeof credential.id === "string" ? credential.id : "credential";
  const idSuffix = id.includes(":")
    ? (id.split(":").pop()?.slice(0, 8) ?? "unknown")
    : id.slice(0, 8) || "unknown";
  return `${typeSlug || "credential"}-${idSuffix || "unknown"}`;
}

/**
 * Normalize the discriminated `CredentialInput` into:
 *   - `displayCredential`: VC-shaped object the PDF / JSON exporters
 *     can read (`id`, `type`, `issuer`, `credentialSubject`, etc.). For
 *     compact-token input this is a synthetic shape from
 *     `decode-for-display.ts` — a `PartialVerifiableCredential`, not a
 *     fully-formed Data Integrity VC.
 *   - `compactToken`: the original token string when the input was a
 *     compact-token, used to override the QR/JSON payload downstream.
 *     Absent for `kind: "vc"` input.
 */
function normalizeInput(input: CredentialInput): {
  displayCredential: PartialVerifiableCredential;
  compactToken?: string;
} {
  switch (input.kind) {
    case "compact-token": {
      const decoded = decodeCompactCredentialForDisplay(input.token);
      // `decode-for-display.ts` types `vcShape` as `Record<string,
      // unknown>` because it's reconstructed from a JWT payload whose
      // claim types aren't statically known. `PartialVerifiableCredential`
      // is the narrowed surface the renderers actually consume — fields
      // like `id`, `type`, `issuer`, `credentialSubject` are always
      // populated by `buildVcShape` (see decode-for-display.ts). The
      // remaining cast acknowledges that synthesis but no longer pretends
      // we have a fully-formed Data Integrity VC.
      return {
        displayCredential: decoded.vcShape as unknown as PartialVerifiableCredential,
        compactToken: decoded.compactToken,
      };
    }
    case "vc": {
      return { displayCredential: input.credential };
    }
  }
}

/**
 * Package a signed credential into the requested formats.
 *
 * Accepts a discriminated `CredentialInput` — `{ kind: "vc", credential }`
 * for a JSON-LD VerifiableCredential, or `{ kind: "compact-token", token }`
 * for a compact `vc-jwt` / `sd-jwt-vc` token string. All packaging
 * happens offline — no network requests.
 *
 * Two error policies are in play:
 *
 *  1. **Per-format errors** (e.g. QR payload exceeds QR capacity, PDF
 *     generator throws on a specific layout) — captured into
 *     `result.errors[]` keyed by format. The HTTP response stays 200,
 *     other formats still come back. This is the "best-effort"
 *     contract callers rely on for batch usage.
 *
 *  2. **Input-shape errors** (e.g. `kind: "compact-token"` but the
 *     `token` isn't a parseable JWT/SD-JWT compact token) —
 *     `normalizeInput` throws `ValidationError` *before* the per-format
 *     loop runs, because the inputs to all formats are derived from the
 *     same shape. The route surfaces this as a 400. No formats run.
 *
 * For compact-token input the QR code embeds the token verbatim (which
 * a verifier can scan + cryptographically validate), the PDF uses the
 * token's payload claims for the certificate layout, and the JSON
 * export wraps the token in a `{ format, credential }` envelope.
 */
export async function packageCredential(
  input: CredentialInput,
  formats: PackageFormat[] = ["qr-png", "qr-svg", "pdf", "json"],
  options?: PackagingOptions,
): Promise<PackagingResult> {
  const { displayCredential, compactToken } = normalizeInput(input);
  const baseName = suggestedBaseName(displayCredential);
  const outputs: PackagedOutput[] = [];
  const errors: Array<{ format: PackageFormat; error: string }> = [];

  // The QR generator takes the same discriminated `CredentialInput` —
  // for `kind: "compact-token"` it embeds the raw token verbatim (no
  // PixelPass), for `kind: "vc"` it PixelPass-compresses the VC JSON.
  // Pass `input` through directly so the discriminator does the
  // right-thing routing on the QR side too.
  for (const format of formats) {
    try {
      switch (format) {
        case "qr-png": {
          const dataUrl = await generateQrPng(input);
          outputs.push({
            format: "qr-png",
            data: dataUrl,
            mimeType: "image/png",
            suggestedFileName: `${baseName}-qr.png`,
          });
          break;
        }
        case "qr-svg": {
          const svg = await generateQrSvg(input);
          outputs.push({
            format: "qr-svg",
            data: svg,
            mimeType: "image/svg+xml",
            suggestedFileName: `${baseName}-qr.svg`,
          });
          break;
        }
        case "pdf": {
          const pdfBuffer = await generatePdf(displayCredential, {
            customization: options?.customization,
            qrPayloadOverride: compactToken,
          });
          outputs.push({
            format: "pdf",
            data: pdfBuffer,
            mimeType: "application/pdf",
            suggestedFileName: `${baseName}.pdf`,
          });
          break;
        }
        case "json": {
          // For compact-token input, export the wrapped token; for
          // JSON-LD input, export the VC. Both use `.json` rather than
          // `.jsonld` — the latter is technically correct for
          // data-integrity VCs (they carry `@context`) but in practice
          // OS / editor / browser tooling does not associate `.jsonld`
          // with anything by default, so attendees can't double-click
          // to open. The mime type is still `application/json`, so the
          // extension change is surface-only.
          const jsonOutput = compactToken
            ? exportAsJson(compactToken)
            : exportAsJson(displayCredential);
          outputs.push({
            format: "json",
            data: jsonOutput,
            mimeType: "application/json",
            suggestedFileName: `${baseName}.json`,
          });
          break;
        }
        case "json-compact": {
          const json = compactToken
            ? exportAsCompactJson(compactToken)
            : exportAsCompactJson(displayCredential);
          outputs.push({
            format: "json-compact",
            data: json,
            mimeType: "application/json",
            suggestedFileName: `${baseName}.json`,
          });
          break;
        }
      }
    } catch (error) {
      errors.push({
        format,
        error: error instanceof Error ? error.message : "Unknown packaging error",
      });
    }
  }

  return { outputs, errors };
}
