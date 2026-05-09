/**
 * PDF-as-input verification.
 *
 * OpenCred-issued PDF certificates carry the underlying credential in two
 * places:
 *
 *   1. **Visible scannable QR** — PixelPass-compressed `OPENCRED1:...` data,
 *      printed on the certificate page so a third party with a phone can
 *      verify it offline.
 *   2. **PDF info-dictionary metadata** — the same `OPENCRED1:...` string,
 *      embedded as a custom key (`OpenCredCredential`) in the PDF's metadata.
 *      Lossless, deterministic, and recoverable without rendering the page.
 *
 * `verifyPdf` reads (2): it parses the PDF's info dictionary, extracts the
 * embedded credential string, decodes it through the existing PixelPass
 * pipeline, and runs the full verification engine on the recovered
 * credential.
 *
 * No PDF page rendering, no QR-image decoding, no native dependencies: the
 * entire path is plaintext metadata extraction. Round-trips with the
 * issuance side at `apps/server/src/packaging/pdf-generator.ts` and
 * `apps/desktop/src/packaging/pdf-generator.ts`, both of which set the same
 * info-dict key when generating PDFs.
 *
 * **Backward compatibility.** PDFs issued before the `OpenCredCredential`
 * info-dict embedding shipped do **not** carry the key. `verifyPdf`
 * returns a `CredentialVerificationResult` with `code: "INVALID"` and a
 * single failed `pdf-embedded-credential` check pointing the user at the
 * QR-scan path on the desktop app. We deliberately do not fall through
 * to PDF rendering and QR-image decoding here — that would require either
 * pulling in a heavy PDF rasteriser or a server-side JS QR decoder, both
 * of which carry meaningful dependency and attack-surface cost. If a user
 * holds a legacy PDF, scanning its visible QR is the supported path.
 *
 * **Encrypted PDFs** are detected explicitly via pdf-lib's `isEncrypted`
 * getter and surfaced with a distinct `pdf-encrypted` check, so users
 * uploading a fresh-but-encrypted OpenCred PDF don't get the misleading
 * "looks like a legacy PDF" message.
 */

import { PDFDict, PDFDocument, PDFHexString, PDFName, PDFString } from "pdf-lib";
import { detectCredentialInputFormat } from "@opencred/shared";

import { decodePixelPass } from "./pixelpass.js";
import type { CredentialVerificationResult, VerifierConfig } from "./types.js";
import { verifyCredential } from "./verifier.js";

/**
 * The PDF info-dictionary key under which the embedded credential is stored.
 *
 * Value is the PixelPass-compressed `OPENCRED1:...` string. The key name is
 * stable across releases — changing it is a backwards-incompatible change.
 */
export const PDF_CREDENTIAL_INFO_KEY = "OpenCredCredential";

/**
 * Verify a PDF that carries an embedded OpenCred credential.
 *
 * @param pdfBytes - The raw PDF file bytes.
 * @param config   - Verifier configuration, forwarded to `verifyCredential`.
 * @returns The verification result, or a synthetic failure result if no
 *          OpenCred-embedded credential is found in the PDF.
 */
export async function verifyPdf(
  pdfBytes: Uint8Array,
  config: VerifierConfig = {},
): Promise<CredentialVerificationResult> {
  let extracted: ExtractResult;
  try {
    extracted = await extractEmbeddedCredential(pdfBytes);
  } catch (err) {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-parse",
          passed: false,
          detail: `Failed to parse PDF: ${err instanceof Error ? err.message : String(err)}`,
        },
      ],
    };
  }

  if (extracted.kind === "encrypted") {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-encrypted",
          passed: false,
          detail:
            "PDF is encrypted; OpenCred cannot read its info dictionary. " +
            "Decrypt the file first, or scan the printed QR code on the certificate page.",
        },
      ],
    };
  }

  if (extracted.kind === "missing") {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-embedded-credential",
          passed: false,
          detail:
            "PDF does not contain an embedded OpenCred credential. " +
            "This may be a PDF issued before the OpenCredCredential info-dict embedding shipped, " +
            "or a PDF not produced by OpenCred at all. " +
            "To verify it, scan its printed QR code with the desktop app or extract the embedded JSON manually.",
        },
      ],
    };
  }

  const embedded = extracted.value;

  // The embedded value mirrors what the visible QR encodes — see the
  // issuance side at `apps/server/src/packaging/pdf-generator.ts` and the
  // desktop equivalent. For full Verifiable Credentials this is the
  // PixelPass-compressed `OPENCRED1:...` blob; for compact tokens
  // (vc-jwt, sd-jwt-vc) it's the raw token. Dispatch by format detection
  // exactly like the server's `/v1/credentials/verify` route does for
  // string inputs.
  const format = detectCredentialInputFormat(embedded);

  let credentialForVerify: Record<string, unknown> | string;
  try {
    switch (format) {
      case "pixelpass":
        credentialForVerify = JSON.parse(decodePixelPass(embedded));
        break;
      case "json":
        credentialForVerify = JSON.parse(embedded);
        break;
      case "jwt-compact":
        credentialForVerify = embedded;
        break;
      case "unknown":
        return {
          verified: false,
          code: "INVALID",
          checks: [
            {
              name: "pdf-embedded-credential",
              passed: false,
              detail:
                "PDF carries an embedded credential value but its format could not be recognized. " +
                "Expected PixelPass (`OPENCRED1:`), JSON, or a compact JWT/SD-JWT token.",
            },
          ],
        };
    }
  } catch (err) {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-credential-decode",
          passed: false,
          detail: `Embedded credential could not be decoded: ${err instanceof Error ? err.message : String(err)}`,
        },
      ],
    };
  }

  return verifyCredential(credentialForVerify, config);
}

/**
 * Discriminated result from `extractEmbeddedCredential`.
 *
 * - `present`: the info dict carries an `OpenCredCredential` string value.
 * - `encrypted`: the PDF is encrypted, so we treat its metadata as opaque
 *   and report this distinctly. Without this branch, encrypted OpenCred
 *   PDFs would fall through to `missing`, which is misleading.
 * - `missing`: the PDF parsed cleanly but does not carry the key. Could
 *   be a legacy OpenCred PDF or a non-OpenCred PDF; we don't try to
 *   distinguish.
 *
 * @internal
 */
type ExtractResult =
  | { kind: "present"; value: string }
  | { kind: "encrypted" }
  | { kind: "missing" };

/**
 * Extract the embedded `OpenCredCredential` value from a PDF's info dictionary.
 *
 * Throws only if the PDF itself is unparseable; encryption and missing-key
 * are reported as discriminated values so the caller can give the user a
 * targeted error message.
 *
 * @internal
 */
async function extractEmbeddedCredential(pdfBytes: Uint8Array): Promise<ExtractResult> {
  // We never sign, edit, or re-emit the PDF — read-only is fine. Pass
  // `ignoreEncryption: true` so the load itself doesn't throw on encrypted
  // PDFs; we'll detect encryption explicitly via `isEncrypted` and route
  // it through the `encrypted` arm so users get a precise error.
  const doc = await PDFDocument.load(pdfBytes, {
    updateMetadata: false,
    ignoreEncryption: true,
  });

  if (doc.isEncrypted) {
    return { kind: "encrypted" };
  }

  const infoRef = doc.context.trailerInfo.Info;
  if (!infoRef) return { kind: "missing" };

  const infoDict = doc.context.lookup(infoRef, PDFDict);
  if (!infoDict) return { kind: "missing" };

  const raw = infoDict.lookup(PDFName.of(PDF_CREDENTIAL_INFO_KEY));
  if (!raw) return { kind: "missing" };

  // PDF strings reach pdf-lib as either PDFString (literal `(...)` form)
  // or PDFHexString (hex `<...>` form). The issuance side writes via
  // PDFKit's literal-string serializer, so PDFString is the common path,
  // but PDFs produced by other tools (LibreOffice, Word, anything that
  // hex-encodes non-ASCII info values) emit PDFHexString — we accept
  // both. Other PDF object types under this key are treated as absent
  // rather than crashing.
  if (raw instanceof PDFString) return { kind: "present", value: raw.asString() };
  if (raw instanceof PDFHexString) return { kind: "present", value: raw.decodeText() };
  return { kind: "missing" };
}
