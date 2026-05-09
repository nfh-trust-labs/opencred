/**
 * PDF certificate generator for Verifiable Credentials.
 *
 * Generates professional certificate-style PDFs with an embedded QR code
 * containing the signed credential. Works completely offline.
 *
 * Layout:
 *  - Certificate border and header
 *  - Credential type and ID
 *  - Issuer and subject information
 *  - Credential details (subject fields)
 *  - Validity period
 *  - Digital signature metadata
 *  - QR code (encodes the full VC JSON for scanning)
 *  - Footer with verification instructions
 */

import PDFDocument from "pdfkit";
import type { VerifiableCredential } from "@opencred/vc-core";
import { compressCredentialForQr, generateQrBuffer } from "./qr-generator.js";

/**
 * PDF info-dictionary key that holds the embedded credential.
 *
 * Read by `verifyPdf()` in `@opencred/verification`. The value is the same
 * PixelPass-compressed `OPENCRED1:...` string that's printed into the QR
 * on the certificate page.
 *
 * **What's load-bearing.** The PDF spec (ISO 32000-1) allows arbitrary
 * keys in the info dictionary, but the round-trip here actually relies on
 * a *runtime* property of PDFKit: `PDFDocument.end()` iterates own
 * enumerable string properties of `doc.info` and writes each one into the
 * output info dict. That is not a documented public API, so a future
 * pdfkit upgrade could in principle drop arbitrary keys silently. The
 * verification-side round-trip tests exist to catch exactly that
 * regression.
 *
 * Changing this key name is a backwards-incompatible change; coordinate
 * with the verification side.
 */
const PDF_CREDENTIAL_INFO_KEY = "OpenCredCredential";

// TODO: Import from @opencred/templates once TemplateCustomization is expanded
// with the new fields (backgroundColor, secondaryColor, textColor, etc.)
interface TemplateCustomization {
  primaryColor?: string;
  logoDataUri?: string;
  issuerDisplayName?: string;
  backgroundColor?: string;
  secondaryColor?: string;
  textColor?: string;
  labelColor?: string;
  logoWidth?: number;
  logoHeight?: number;
  footerText?: string;
  sealDataUri?: string;
}

export interface PdfOptions {
  customization?: TemplateCustomization;
}

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

const PAGE_MARGIN = 50;
const CONTENT_LEFT = PAGE_MARGIN + 15;
const CONTENT_WIDTH = 595.28 - 2 * PAGE_MARGIN - 30; // A4 width minus margins and padding
const PAGE_RIGHT = 595.28 - PAGE_MARGIN;
const QR_SIZE = 120;

// Colors
const COLOR_PRIMARY = "#1a365d"; // Dark navy for headings
const COLOR_SECONDARY = "#2d5986"; // Medium blue for subheadings
const COLOR_ACCENT = "#3182ce"; // Blue accent for lines
const COLOR_TEXT = "#1a202c"; // Dark text
const COLOR_LABEL = "#718096"; // Gray labels
const COLOR_MUTED = "#a0aec0"; // Light gray
const COLOR_BORDER = "#2d5986"; // Border color

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(isoDate: string): string {
  try {
    return new Date(isoDate).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return isoDate;
  }
}

function formatLabel(key: string): string {
  return key.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (c) => c.toUpperCase());
}

function getCredentialTitle(credential: VerifiableCredential): string {
  const types = Array.isArray(credential.type) ? credential.type : [String(credential.type)];
  const meaningful = types.filter((t) => t !== "VerifiableCredential");
  if (meaningful.length > 0) {
    return meaningful.map((t) => t.replace(/([a-z])([A-Z])/g, "$1 $2")).join(", ");
  }
  return "Verifiable Credential";
}

function getIssuerDisplay(credential: VerifiableCredential): string {
  return typeof credential.issuer === "string" ? credential.issuer : credential.issuer.id;
}

function drawHorizontalRule(
  doc: PDFKit.PDFDocument,
  y: number,
  color = COLOR_ACCENT,
  width = 1,
): void {
  doc
    .strokeColor(color)
    .lineWidth(width)
    .moveTo(CONTENT_LEFT, y)
    .lineTo(PAGE_RIGHT - 15, y)
    .stroke();
}

function drawSectionHeader(
  doc: PDFKit.PDFDocument,
  title: string,
  headingColor = COLOR_SECONDARY,
): void {
  const y = doc.y;
  drawHorizontalRule(doc, y, COLOR_MUTED, 0.5);
  doc.moveDown(0.6);
  doc
    .font("Helvetica-Bold")
    .fontSize(9)
    .fillColor(headingColor)
    .text(title.toUpperCase(), CONTENT_LEFT);
  doc.moveDown(0.4);
}

function drawLabelValue(
  doc: PDFKit.PDFDocument,
  label: string,
  value: string,
  labelWidth = 120,
  lblColor = COLOR_LABEL,
  valColor = COLOR_TEXT,
): void {
  const y = doc.y;
  doc.font("Helvetica").fontSize(9).fillColor(lblColor).text(label, CONTENT_LEFT, y, {
    width: labelWidth,
    continued: false,
  });
  doc
    .font("Helvetica")
    .fontSize(9)
    .fillColor(valColor)
    .text(value, CONTENT_LEFT + labelWidth, y, {
      width: CONTENT_WIDTH - labelWidth,
    });
  // Move to whichever is lower (label or wrapped value)
  doc.y = Math.max(doc.y, y + 14);
}

// ---------------------------------------------------------------------------
// QR code generation (uses PixelPass compression via qr-generator)
// ---------------------------------------------------------------------------

async function generateQrPngBuffer(credential: VerifiableCredential): Promise<Buffer | null> {
  try {
    return await generateQrBuffer(credential);
  } catch {
    return null; // Too large even after compression — skip QR in PDF
  }
}

// ---------------------------------------------------------------------------
// PDF generation
// ---------------------------------------------------------------------------

/**
 * Generate a professional PDF certificate from a VerifiableCredential.
 *
 * The PDF includes a QR code encoding the full credential JSON. If the
 * credential is too large for a QR code (>2953 bytes), the QR is omitted
 * and a note is shown instead.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A Buffer containing the PDF document.
 */
export async function generatePdf(
  credential: VerifiableCredential,
  options?: PdfOptions,
): Promise<Buffer> {
  // Generate QR code first (async), then build PDF
  const qrBuffer = await generateQrPngBuffer(credential);

  // Same payload the QR encodes, embedded into the PDF info dictionary so
  // verifiers can recover the credential from the file directly without
  // having to render the page or scan the QR. Read by `verifyPdf()` in
  // `@opencred/verification`.
  const embeddedCredential = compressCredentialForQr(credential);

  const customization = options?.customization;
  const accentColor = customization?.primaryColor ?? COLOR_ACCENT;
  const primaryHeadingColor = customization?.primaryColor ?? COLOR_PRIMARY;
  const borderColor = customization?.primaryColor ?? COLOR_BORDER;
  const bgColor = customization?.backgroundColor ?? "#ffffff";
  const secondaryColor = customization?.secondaryColor ?? COLOR_SECONDARY;
  const textColor = customization?.textColor ?? COLOR_TEXT;
  const labelColor = customization?.labelColor ?? COLOR_LABEL;
  const issuerDisplay = customization?.issuerDisplayName ?? getIssuerDisplay(credential);
  const footerText =
    customization?.footerText ??
    "This certificate was generated by OpenCred Desktop. The credential is digitally signed and can be independently verified.";
  const logoUri = customization?.logoDataUri;
  const logoW = customization?.logoWidth ?? 60;
  const logoH = customization?.logoHeight ?? 60;
  const sealUri = customization?.sealDataUri;

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: "A4",
        margin: PAGE_MARGIN,
        info: {
          Title: `${getCredentialTitle(credential)} Certificate`,
          Author: "OpenCred Desktop",
          Subject: `Credential: ${credential.id}`,
          Creator: "OpenCred",
        },
      });

      // Custom info-dict key carrying the credential payload. PDFKit's
      // `DocumentInfo` type only enumerates standard PDF keys (Title /
      // Author / Subject / etc.) but the runtime preserves arbitrary
      // string keys on `doc.info` and writes them through to the PDF info
      // dictionary verbatim. Read at verification time by `verifyPdf()`
      // in `@opencred/verification`.
      (doc.info as unknown as Record<string, string>)[PDF_CREDENTIAL_INFO_KEY] =
        embeddedCredential;

      const buffers: Buffer[] = [];
      doc.on("data", (chunk: Buffer) => buffers.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(buffers)));
      doc.on("error", reject);

      // ---------------------------------------------------------------
      // Page background
      // ---------------------------------------------------------------
      if (bgColor !== "#ffffff") {
        doc.rect(0, 0, 595.28, 841.89).fill(bgColor);
      }

      // ---------------------------------------------------------------
      // Certificate border
      // ---------------------------------------------------------------
      doc
        .rect(
          PAGE_MARGIN - 5,
          PAGE_MARGIN - 5,
          595.28 - 2 * PAGE_MARGIN + 10,
          841.89 - 2 * PAGE_MARGIN + 10,
        )
        .strokeColor(borderColor)
        .lineWidth(2)
        .stroke();

      // Inner decorative border
      doc
        .rect(
          PAGE_MARGIN + 3,
          PAGE_MARGIN + 3,
          595.28 - 2 * PAGE_MARGIN - 6,
          841.89 - 2 * PAGE_MARGIN - 6,
        )
        .strokeColor(COLOR_MUTED)
        .lineWidth(0.5)
        .stroke();

      // ---------------------------------------------------------------
      // Header
      // ---------------------------------------------------------------
      doc.moveDown(1.5);

      // Logo (above header if provided)
      if (logoUri) {
        try {
          const logoBuffer = Buffer.from(logoUri.split(",")[1], "base64");
          const logoX = (595.28 - logoW) / 2;
          doc.image(logoBuffer, logoX, doc.y, { width: logoW, height: logoH });
          doc.y += logoH + 8;
        } catch {
          /* skip invalid logo data */
        }
      }

      // Top accent line
      const accentY = doc.y;
      doc
        .strokeColor(accentColor)
        .lineWidth(3)
        .moveTo(CONTENT_LEFT + 60, accentY)
        .lineTo(PAGE_RIGHT - 75, accentY)
        .stroke();

      doc.moveDown(1);

      // "CERTIFICATE OF"
      doc
        .font("Helvetica")
        .fontSize(11)
        .fillColor(labelColor)
        .text("CERTIFICATE OF", { align: "center" });

      doc.moveDown(0.3);

      // Credential type (main title)
      doc
        .font("Helvetica-Bold")
        .fontSize(22)
        .fillColor(primaryHeadingColor)
        .text(getCredentialTitle(credential), { align: "center" });

      doc.moveDown(0.8);

      // Bottom accent line
      const accentY2 = doc.y;
      doc
        .strokeColor(accentColor)
        .lineWidth(3)
        .moveTo(CONTENT_LEFT + 60, accentY2)
        .lineTo(PAGE_RIGHT - 75, accentY2)
        .stroke();

      doc.moveDown(1.2);

      // ---------------------------------------------------------------
      // Credential ID
      // ---------------------------------------------------------------
      doc
        .font("Helvetica")
        .fontSize(7)
        .fillColor(COLOR_MUTED)
        .text(`ID: ${credential.id}`, { align: "center" });

      doc.moveDown(1.5);

      // ---------------------------------------------------------------
      // Issuer & Subject + QR code
      // ---------------------------------------------------------------
      const issuerSectionY = doc.y;

      // Left column: Issuer and Subject info
      const leftColWidth = qrBuffer ? CONTENT_WIDTH - QR_SIZE - 30 : CONTENT_WIDTH;

      doc.font("Helvetica").fontSize(9).fillColor(labelColor).text("ISSUED BY", CONTENT_LEFT);
      doc.moveDown(0.2);
      doc
        .font("Helvetica-Bold")
        .fontSize(11)
        .fillColor(textColor)
        .text(issuerDisplay, CONTENT_LEFT, doc.y, { width: leftColWidth });
      doc.moveDown(0.8);

      // Subject ID (if present)
      const subject = credential.credentialSubject;
      if (subject.id) {
        doc.font("Helvetica").fontSize(9).fillColor(labelColor).text("ISSUED TO", CONTENT_LEFT);
        doc.moveDown(0.2);
        doc
          .font("Helvetica-Bold")
          .fontSize(11)
          .fillColor(textColor)
          .text(String(subject.id), CONTENT_LEFT, doc.y, { width: leftColWidth });
        doc.moveDown(0.8);
      }

      // Validity dates (compact, in the left column)
      doc.font("Helvetica").fontSize(9).fillColor(labelColor).text("VALIDITY PERIOD", CONTENT_LEFT);
      doc.moveDown(0.2);
      const validFromStr = formatDate(credential.validFrom);
      const validUntilStr = credential.validUntil
        ? formatDate(credential.validUntil)
        : "No expiration";
      doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor(textColor)
        .text(`${validFromStr}  —  ${validUntilStr}`, CONTENT_LEFT, doc.y, { width: leftColWidth });

      const afterLeftCol = doc.y;

      // Right column: QR code
      if (qrBuffer) {
        const qrX = PAGE_RIGHT - 15 - QR_SIZE;
        const qrY = issuerSectionY;
        doc.image(qrBuffer, qrX, qrY, { width: QR_SIZE, height: QR_SIZE });

        // QR label
        doc
          .font("Helvetica")
          .fontSize(6)
          .fillColor(COLOR_MUTED)
          .text("Scan to verify", qrX, qrY + QR_SIZE + 3, {
            width: QR_SIZE,
            align: "center",
          });
      }

      doc.y = Math.max(afterLeftCol, issuerSectionY + QR_SIZE + 20);
      doc.moveDown(1);

      // ---------------------------------------------------------------
      // Credential Details (subject fields)
      // ---------------------------------------------------------------
      const subjectEntries = Object.entries(subject).filter(([key]) => key !== "id");

      if (subjectEntries.length > 0) {
        drawSectionHeader(doc, "Credential Details", secondaryColor);

        for (const [key, value] of subjectEntries) {
          if (typeof value === "object" && value !== null) {
            drawLabelValue(doc, formatLabel(key), "", 120, labelColor, textColor);
            for (const [subKey, subValue] of Object.entries(value as Record<string, unknown>)) {
              drawLabelValue(
                doc,
                `  ${formatLabel(subKey)}`,
                String(subValue ?? ""),
                130,
                labelColor,
                textColor,
              );
            }
          } else {
            drawLabelValue(doc, formatLabel(key), String(value ?? ""), 120, labelColor, textColor);
          }
        }

        doc.moveDown(0.5);
      }

      // ---------------------------------------------------------------
      // Digital Signature
      // ---------------------------------------------------------------
      drawSectionHeader(doc, "Digital Signature", secondaryColor);

      drawLabelValue(doc, "Proof Type", credential.proof.type, 120, labelColor, textColor);
      if (credential.proof.cryptosuite) {
        drawLabelValue(
          doc,
          "Cryptosuite",
          credential.proof.cryptosuite,
          120,
          labelColor,
          textColor,
        );
      }
      drawLabelValue(
        doc,
        "Created",
        formatDate(credential.proof.created),
        120,
        labelColor,
        textColor,
      );
      drawLabelValue(
        doc,
        "Verification Method",
        credential.proof.verificationMethod,
        120,
        labelColor,
        textColor,
      );

      // X.509 chain info (if present)
      const proof = credential.proof as Record<string, unknown>;
      if (Array.isArray(proof.x5c) && proof.x5c.length > 0) {
        drawLabelValue(
          doc,
          "Certificate Chain",
          `${proof.x5c.length} certificate(s) embedded`,
          120,
          labelColor,
          textColor,
        );
      }

      doc.moveDown(1);

      // ---------------------------------------------------------------
      // Seal (before footer)
      // ---------------------------------------------------------------
      if (sealUri) {
        try {
          const sealBuffer = Buffer.from(sealUri.split(",")[1], "base64");
          const sealSize = 50;
          const sealX = (595.28 - sealSize) / 2;
          doc.image(sealBuffer, sealX, doc.y, { width: sealSize, height: sealSize });
          doc.y += sealSize + 8;
        } catch {
          /* skip invalid seal data */
        }
      }

      // ---------------------------------------------------------------
      // Footer
      // ---------------------------------------------------------------
      drawHorizontalRule(doc, doc.y, COLOR_MUTED, 0.5);
      doc.moveDown(0.8);

      if (!qrBuffer) {
        doc
          .font("Helvetica")
          .fontSize(7)
          .fillColor(COLOR_MUTED)
          .text(
            "This credential is too large for a QR code. Use the JSON-LD export to share the full credential data.",
            CONTENT_LEFT,
            doc.y,
            { width: CONTENT_WIDTH, align: "center" },
          );
        doc.moveDown(0.5);
      }

      doc
        .font("Helvetica")
        .fontSize(7)
        .fillColor(COLOR_MUTED)
        .text(footerText, CONTENT_LEFT, doc.y, { width: CONTENT_WIDTH, align: "center" });

      doc.moveDown(0.3);

      doc
        .font("Helvetica")
        .fontSize(6)
        .fillColor(COLOR_MUTED)
        .text(`Generated: ${formatDate(new Date().toISOString())}`, CONTENT_LEFT, doc.y, {
          width: CONTENT_WIDTH,
          align: "center",
        });

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
}
