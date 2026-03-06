/**
 * Generate a PDF certificate for a Verifiable Credential with an embedded QR code.
 *
 * Uses jsPDF for PDF generation and qrcode for QR code generation.
 * Runs entirely client-side — no network requests.
 */

import { jsPDF } from "jspdf";
import QRCode from "qrcode";

interface CredentialPdfOptions {
  credential: Record<string, unknown> | string;
  schemaId?: string;
  proofMechanism?: string;
}

/**
 * Extract human-readable fields from a credential for display in the PDF.
 */
function extractDisplayFields(credential: Record<string, unknown> | string): {
  issuer: string;
  type: string;
  subject: Record<string, string>;
  validFrom?: string;
  validUntil?: string;
} {
  if (typeof credential === "string") {
    // JWS — decode the payload
    const parts = credential.split(".");
    if (parts.length >= 2) {
      try {
        const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
        return extractDisplayFields(payload);
      } catch {
        return { issuer: "Unknown", type: "Verifiable Credential", subject: {} };
      }
    }
    return { issuer: "Unknown", type: "Verifiable Credential", subject: {} };
  }

  const issuer =
    typeof credential.issuer === "string"
      ? credential.issuer
      : (credential.issuer as Record<string, unknown>)?.id as string ?? "Unknown";

  const types = Array.isArray(credential.type) ? credential.type : [credential.type];
  const type = types.find((t) => t !== "VerifiableCredential") ?? "Verifiable Credential";

  const rawSubject = credential.credentialSubject as Record<string, unknown> | undefined;
  const subject: Record<string, string> = {};
  if (rawSubject) {
    for (const [key, value] of Object.entries(rawSubject)) {
      if (key === "id") continue;
      if (typeof value === "string" || typeof value === "number") {
        subject[key] = String(value);
      }
    }
  }

  return {
    issuer,
    type,
    subject,
    validFrom: credential.validFrom as string | undefined,
    validUntil: credential.validUntil as string | undefined,
  };
}

/**
 * Format a field name from camelCase to Title Case.
 */
function formatFieldName(name: string): string {
  return name
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (s) => s.toUpperCase())
    .trim();
}

/**
 * Generate a PDF with credential details and a QR code containing the credential.
 */
export async function generateCredentialPdf(options: CredentialPdfOptions): Promise<Blob> {
  const { credential, proofMechanism } = options;
  const display = extractDisplayFields(credential);

  // Serialize credential for QR
  const credentialString =
    typeof credential === "string" ? credential : JSON.stringify(credential);

  // Generate QR code as data URL
  let qrDataUrl: string;
  const qrTooLarge = credentialString.length > 2953;
  if (qrTooLarge) {
    // QR code can't hold the full credential — generate a placeholder message
    qrDataUrl = await QRCode.toDataURL("Credential too large for QR. See embedded JSON.", {
      errorCorrectionLevel: "M",
      width: 300,
      margin: 2,
    });
  } else {
    qrDataUrl = await QRCode.toDataURL(credentialString, {
      errorCorrectionLevel: "L",
      width: 300,
      margin: 2,
    });
  }

  // Create PDF
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 20;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  // Header bar
  doc.setFillColor(17, 24, 39); // gray-900
  doc.rect(0, 0, pageWidth, 35, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(20);
  doc.setFont("helvetica", "bold");
  doc.text("OpenCred", margin, 15);
  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.text("Verifiable Credential Certificate", margin, 24);

  // Proof format badge
  if (proofMechanism) {
    const badgeText =
      proofMechanism === "data-integrity"
        ? "Data Integrity (ECDSA)"
        : proofMechanism === "eddsa-di"
          ? "Data Integrity (EdDSA)"
          : proofMechanism === "jws"
            ? "JWS (VC-JOSE-COSE)"
            : proofMechanism === "vc-jwt"
              ? "VC-JWT"
              : proofMechanism === "sd-jwt-vc"
                ? "SD-JWT VC"
                : proofMechanism;
    doc.setFontSize(8);
    const badgeWidth = doc.getTextWidth(badgeText) + 8;
    doc.setFillColor(139, 92, 246); // purple
    doc.roundedRect(pageWidth - margin - badgeWidth, 19, badgeWidth, 7, 2, 2, "F");
    doc.text(badgeText, pageWidth - margin - badgeWidth + 4, 24);
  }

  y = 45;

  // Credential type title
  doc.setTextColor(17, 24, 39);
  doc.setFontSize(16);
  doc.setFont("helvetica", "bold");
  doc.text(display.type, margin, y);
  y += 10;

  // Divider
  doc.setDrawColor(229, 231, 235);
  doc.setLineWidth(0.5);
  doc.line(margin, y, pageWidth - margin, y);
  y += 8;

  // Issuer
  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(107, 114, 128); // gray-500
  doc.text("ISSUER", margin, y);
  y += 5;
  doc.setFontSize(10);
  doc.setTextColor(17, 24, 39);
  doc.setFont("helvetica", "normal");
  // Wrap long issuer DIDs
  const issuerLines = doc.splitTextToSize(display.issuer, contentWidth);
  doc.text(issuerLines, margin, y);
  y += issuerLines.length * 5 + 6;

  // Validity
  if (display.validFrom || display.validUntil) {
    doc.setFontSize(9);
    doc.setTextColor(107, 114, 128);
    doc.text("VALIDITY", margin, y);
    y += 5;
    doc.setFontSize(10);
    doc.setTextColor(17, 24, 39);
    const validityParts: string[] = [];
    if (display.validFrom) validityParts.push(`From: ${display.validFrom.split("T")[0]}`);
    if (display.validUntil) validityParts.push(`Until: ${display.validUntil.split("T")[0]}`);
    doc.text(validityParts.join("    "), margin, y);
    y += 8;
  }

  // Divider
  doc.setDrawColor(229, 231, 235);
  doc.line(margin, y, pageWidth - margin, y);
  y += 8;

  // Subject fields
  doc.setFontSize(9);
  doc.setTextColor(107, 114, 128);
  doc.text("CREDENTIAL SUBJECT", margin, y);
  y += 7;

  for (const [key, value] of Object.entries(display.subject)) {
    doc.setFontSize(9);
    doc.setTextColor(107, 114, 128);
    doc.text(formatFieldName(key), margin, y);
    doc.setFontSize(10);
    doc.setTextColor(17, 24, 39);
    doc.text(value, margin + 50, y);
    y += 6;
  }

  y += 6;

  // Divider
  doc.setDrawColor(229, 231, 235);
  doc.line(margin, y, pageWidth - margin, y);
  y += 8;

  // QR Code section
  doc.setFontSize(9);
  doc.setTextColor(107, 114, 128);
  doc.text("SIGNED CREDENTIAL (QR CODE)", margin, y);
  y += 5;

  if (qrTooLarge) {
    doc.setFontSize(8);
    doc.setTextColor(180, 83, 9); // amber-700
    doc.text("Credential exceeds QR capacity. QR contains a reference message only.", margin, y);
    y += 5;
  }

  // Center QR code
  const qrSize = 55;
  const qrX = (pageWidth - qrSize) / 2;
  doc.addImage(qrDataUrl, "PNG", qrX, y, qrSize, qrSize);
  y += qrSize + 8;

  // Footer
  doc.setFontSize(8);
  doc.setTextColor(156, 163, 175); // gray-400
  doc.text(`Generated by OpenCred on ${new Date().toISOString().split("T")[0]}`, margin, y);
  doc.text("Scan the QR code to verify this credential", margin, y + 4);

  return doc.output("blob");
}
