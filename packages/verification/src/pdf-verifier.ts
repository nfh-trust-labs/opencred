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
 * **Backward compatibility.** PDFs issued before this metadata embedding
 * was added (v1.2.0 and earlier) do **not** carry the `OpenCredCredential`
 * key. `verifyPdf` returns a `CredentialVerificationResult` with
 * `code: "INVALID"` and a single failed `pdf-embedded-credential` check
 * pointing the user at the QR-scan path on the desktop app. We deliberately
 * do not fall through to PDF rendering and QR-image decoding here — that
 * would require either pulling in a heavy PDF rasteriser or a server-side
 * JS QR decoder, both of which carry meaningful dependency and attack-
 * surface cost. If a user holds a legacy PDF, scanning its visible QR is
 * the supported path.
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
  let embedded: string | undefined;
  try {
    embedded = await extractEmbeddedCredential(pdfBytes);
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

  if (!embedded) {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-embedded-credential",
          passed: false,
          detail:
            "PDF does not contain an embedded OpenCred credential. " +
            "This may be a legacy PDF (pre-v1.2.1) or a PDF not produced by OpenCred. " +
            "To verify a legacy PDF, scan its printed QR code with the desktop app or extract the embedded JSON manually.",
        },
      ],
    };
  }

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
 * Extract the embedded `OpenCredCredential` value from a PDF's info dictionary.
 *
 * Returns `undefined` if the PDF parses successfully but does not contain
 * the key. Throws if the PDF itself is unparseable.
 *
 * @internal
 */
async function extractEmbeddedCredential(pdfBytes: Uint8Array): Promise<string | undefined> {
  const doc = await PDFDocument.load(pdfBytes, {
    // We never sign, edit, or re-emit the PDF — read-only is fine.
    updateMetadata: false,
    // Don't throw on encrypted PDFs; we just won't be able to read their
    // info dict, which surfaces as "key not found" anyway.
    ignoreEncryption: true,
  });

  const infoRef = doc.context.trailerInfo.Info;
  if (!infoRef) return undefined;

  const infoDict = doc.context.lookup(infoRef, PDFDict);
  if (!infoDict) return undefined;

  const raw = infoDict.lookup(PDFName.of(PDF_CREDENTIAL_INFO_KEY));
  if (!raw) return undefined;

  if (raw instanceof PDFString) return raw.asString();
  if (raw instanceof PDFHexString) return raw.decodeText();

  // Unrecognized PDF object type for the value — treat as absent rather
  // than crashing. Issuance-side writes via PDFKit produce PDFString.
  return undefined;
}
