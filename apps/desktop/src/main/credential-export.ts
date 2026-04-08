/**
 * Credential template rendering and export.
 *
 * Renders signed credentials as SVGs using the @opencred/templates package,
 * exports credentials as JSON-LD, generates QR code data URIs, and packages
 * credentials into multiple export formats.
 *
 * All operations work completely offline — no network requests.
 *
 * SECURITY NOTE: This module handles signed credentials (public data).
 * It NEVER touches private keys or signing buffers.
 */

import QRCode from "qrcode";
import { getTemplate, renderSvg } from "@opencred/templates";
import type { TemplateCustomization } from "@opencred/templates";
import type { VerifiableCredential, Issuer } from "@opencred/vc-core";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single packaged output item. */
export interface PackagedOutput {
  /** The export format identifier. */
  format: string;
  /** The output data (string for text formats, base64 data URI for binary). */
  data: string;
  /** MIME type of the output. */
  mimeType: string;
  /** Suggested file name for saving. */
  suggestedFileName: string;
}

// ---------------------------------------------------------------------------
// Extraction helpers (exported for testing)
// ---------------------------------------------------------------------------

/**
 * Extract the issuer name from a credential.
 *
 * - If issuer is a string, return it directly.
 * - If issuer is an object with `name`, return the name.
 * - If issuer is an object without `name`, return the `id`.
 */
export function extractIssuerName(credential: VerifiableCredential): string {
  const issuer: Issuer = credential.issuer;
  if (typeof issuer === "string") {
    return issuer;
  }
  return issuer.name ?? issuer.id;
}

/**
 * Extract the credential title from the type array.
 *
 * Uses the last type that is not "VerifiableCredential". If there are no
 * other types, falls back to "Verifiable Credential".
 */
export function extractCredentialTitle(credential: VerifiableCredential): string {
  const customTypes = credential.type.filter((t) => t !== "VerifiableCredential");
  if (customTypes.length > 0) {
    return customTypes[customTypes.length - 1];
  }
  return "Verifiable Credential";
}

/**
 * Extract subject fields from credentialSubject, flattened to string values.
 *
 * Converts all values to strings. Skips values that are objects or arrays
 * (non-primitive) since SVG templates expect flat string values.
 */
export function extractSubjectFields(credential: VerifiableCredential): Record<string, string> {
  const subject = credential.credentialSubject;
  const fields: Record<string, string> = {};

  for (const [key, value] of Object.entries(subject)) {
    if (value === null || value === undefined) {
      continue;
    }
    if (typeof value === "object") {
      // Skip complex nested objects — templates expect flat strings
      continue;
    }
    fields[key] = String(value);
  }

  return fields;
}

/**
 * Generate a suggested base file name from a credential.
 */
function suggestedBaseName(credential: VerifiableCredential): string {
  const customTypes = credential.type.filter((t) => t !== "VerifiableCredential");
  const typeSlug =
    customTypes.length > 0
      ? customTypes[0].replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase()
      : "credential";
  const idSuffix = credential.id.includes(":")
    ? (credential.id.split(":").pop()?.slice(0, 8) ?? "unknown")
    : credential.id.slice(0, 8);
  return `${typeSlug}-${idSuffix}`;
}

// ---------------------------------------------------------------------------
// Export functions
// ---------------------------------------------------------------------------

/**
 * Render a signed credential as SVG using the templates package.
 *
 * Extracts issuer name, credential title, dates, and subject fields from the
 * credential, then renders the appropriate template.
 *
 * @param credential - The signed VerifiableCredential.
 * @param schemaId - Schema ID to look up the template.
 * @param customization - Optional template customization (colors, logo, etc.).
 * @returns The rendered SVG string.
 */
export function renderCredentialSvg(
  credential: VerifiableCredential,
  schemaId: string,
  customization?: TemplateCustomization,
): string {
  const template = getTemplate(schemaId);
  const issuerName = extractIssuerName(credential);
  const credentialTitle = extractCredentialTitle(credential);
  const subject = extractSubjectFields(credential);

  return renderSvg(template.svg, {
    values: {
      issuerName,
      credentialTitle,
      validFrom: credential.validFrom,
      validUntil: credential.validUntil,
      subject,
    },
    customization,
  });
}

/**
 * Export a credential as JSON-LD (formatted JSON string).
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A pretty-printed JSON string.
 */
export function exportAsJsonLd(credential: VerifiableCredential): string {
  return JSON.stringify(credential, null, 2);
}

/**
 * Export a credential as a QR code data URI (PNG base64).
 *
 * The QR encodes the credential JSON. If the credential is too large for a
 * QR code, the function throws.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A PNG data URL (base64-encoded).
 */
export async function exportAsQrCode(credential: VerifiableCredential): Promise<string> {
  const json = JSON.stringify(credential);
  return QRCode.toDataURL(json, {
    errorCorrectionLevel: "L",
    type: "image/png",
    margin: 2,
    width: 400,
  });
}

/**
 * Package a credential into multiple export formats.
 *
 * Supported formats:
 * - "json-ld" — formatted JSON-LD string
 * - "svg"     — rendered SVG from template
 * - "qr"      — QR code as PNG data URI
 *
 * @param credential - The signed VerifiableCredential.
 * @param schemaId - Schema ID for template lookup.
 * @param formats - Array of format identifiers to produce.
 * @param customization - Optional template customization.
 * @returns Array of packaged outputs.
 */
export async function packageCredential(
  credential: VerifiableCredential,
  schemaId: string,
  formats: string[],
  customization?: TemplateCustomization,
): Promise<PackagedOutput[]> {
  const baseName = suggestedBaseName(credential);
  const outputs: PackagedOutput[] = [];

  for (const format of formats) {
    switch (format) {
      case "json-ld": {
        const jsonLd = exportAsJsonLd(credential);
        outputs.push({
          format: "json-ld",
          data: jsonLd,
          mimeType: "application/ld+json",
          suggestedFileName: `${baseName}.jsonld`,
        });
        break;
      }
      case "svg": {
        const svg = renderCredentialSvg(credential, schemaId, customization);
        outputs.push({
          format: "svg",
          data: svg,
          mimeType: "image/svg+xml",
          suggestedFileName: `${baseName}.svg`,
        });
        break;
      }
      case "qr": {
        const qrDataUri = await exportAsQrCode(credential);
        outputs.push({
          format: "qr",
          data: qrDataUri,
          mimeType: "image/png",
          suggestedFileName: `${baseName}-qr.png`,
        });
        break;
      }
    }
  }

  return outputs;
}
