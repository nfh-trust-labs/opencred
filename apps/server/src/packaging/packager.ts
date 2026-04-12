/**
 * Credential packager — orchestrates offline packaging of signed VCs.
 *
 * Takes a VerifiableCredential and produces QR codes (PNG/SVG), PDF
 * certificates, and JSON-LD exports. All operations work completely
 * offline — no network requests.
 */

import type { VerifiableCredential } from "@opencred/vc-core";
import type { TemplateCustomization } from "@opencred/templates";
import { generateQrPng, generateQrSvg } from "./qr-generator.js";

// Re-export for use by verification and other consumers
export { decodeQrData } from "./qr-generator.js";
import { generatePdf } from "./pdf-generator.js";
import { exportAsJsonLd, exportAsCompactJson } from "./json-export.js";

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
export type PackageFormat = "qr-png" | "qr-svg" | "pdf" | "json-ld" | "json-compact";

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
 * Generate a suggested file name base from a credential.
 */
function suggestedBaseName(credential: VerifiableCredential): string {
  const types = credential.type.filter((t) => t !== "VerifiableCredential");
  const typeSlug =
    types.length > 0 ? types[0].replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase() : "credential";
  const idSuffix = credential.id.includes(":")
    ? (credential.id.split(":").pop()?.slice(0, 8) ?? "unknown")
    : credential.id.slice(0, 8);
  return `${typeSlug}-${idSuffix}`;
}

/**
 * Package a signed VerifiableCredential into the requested formats.
 *
 * All packaging happens offline — no network requests. If a specific
 * format fails (e.g., QR exceeds capacity), the error is captured in
 * the result rather than throwing.
 *
 * @param credential - The signed VerifiableCredential.
 * @param formats - The output formats to produce. Defaults to all formats.
 * @returns PackagingResult with outputs and any errors.
 */
export async function packageCredential(
  credential: VerifiableCredential,
  formats: PackageFormat[] = ["qr-png", "qr-svg", "pdf", "json-ld"],
  options?: PackagingOptions,
): Promise<PackagingResult> {
  const baseName = suggestedBaseName(credential);
  const outputs: PackagedOutput[] = [];
  const errors: Array<{ format: PackageFormat; error: string }> = [];

  for (const format of formats) {
    try {
      switch (format) {
        case "qr-png": {
          const dataUrl = await generateQrPng(credential);
          outputs.push({
            format: "qr-png",
            data: dataUrl,
            mimeType: "image/png",
            suggestedFileName: `${baseName}-qr.png`,
          });
          break;
        }
        case "qr-svg": {
          const svg = await generateQrSvg(credential);
          outputs.push({
            format: "qr-svg",
            data: svg,
            mimeType: "image/svg+xml",
            suggestedFileName: `${baseName}-qr.svg`,
          });
          break;
        }
        case "pdf": {
          const pdfBuffer = await generatePdf(credential, { customization: options?.customization });
          outputs.push({
            format: "pdf",
            data: pdfBuffer,
            mimeType: "application/pdf",
            suggestedFileName: `${baseName}.pdf`,
          });
          break;
        }
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
        case "json-compact": {
          const json = exportAsCompactJson(credential);
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
