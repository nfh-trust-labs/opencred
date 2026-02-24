import PDFDocument from "pdfkit";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CredentialPdfInput {
  credential: Record<string, unknown>;
  /** PNG buffer of the QR code to embed. If omitted the PDF omits the QR section. */
  qrBuffer?: Buffer;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a human-readable PDF for a Verifiable Credential.
 *
 * Layout:
 *  1. Title
 *  2. Credential type(s)
 *  3. Issuer info
 *  4. Subject fields (key-value pairs)
 *  5. Validity dates
 *  6. QR code image (if provided)
 *  7. Raw JSON (smaller font, machine-readable)
 */
export async function generateCredentialPdf(input: CredentialPdfInput): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: "A4",
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        info: {
          Title: "Verifiable Credential",
          Author: "OpenCred",
        },
      });

      const chunks: Buffer[] = [];
      doc.on("data", (chunk: Buffer) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);

      const vc = input.credential;

      // ----- Title -----
      doc.fontSize(22).font("Helvetica-Bold").text("Verifiable Credential", {
        align: "center",
      });
      doc.moveDown(0.5);

      // Divider
      drawDivider(doc);
      doc.moveDown(0.5);

      // ----- Credential type(s) -----
      const types = extractTypes(vc);
      if (types.length > 0) {
        doc.fontSize(11).font("Helvetica-Bold").text("Type: ", { continued: true });
        doc.font("Helvetica").text(types.join(", "));
        doc.moveDown(0.3);
      }

      // ----- Issuer -----
      const issuerLabel = extractIssuer(vc);
      doc.fontSize(11).font("Helvetica-Bold").text("Issuer: ", { continued: true });
      doc.font("Helvetica").text(issuerLabel);
      doc.moveDown(0.3);

      // ----- Validity dates -----
      if (typeof vc.validFrom === "string") {
        doc.fontSize(11).font("Helvetica-Bold").text("Valid From: ", { continued: true });
        doc.font("Helvetica").text(vc.validFrom);
        doc.moveDown(0.3);
      }
      if (typeof vc.validUntil === "string") {
        doc.fontSize(11).font("Helvetica-Bold").text("Valid Until: ", { continued: true });
        doc.font("Helvetica").text(vc.validUntil);
        doc.moveDown(0.3);
      }
      if (typeof vc.issuanceDate === "string") {
        doc.fontSize(11).font("Helvetica-Bold").text("Issuance Date: ", { continued: true });
        doc.font("Helvetica").text(vc.issuanceDate);
        doc.moveDown(0.3);
      }

      // ----- Subject fields -----
      const subject = extractSubject(vc);
      if (subject && Object.keys(subject).length > 0) {
        doc.moveDown(0.3);
        drawDivider(doc);
        doc.moveDown(0.3);
        doc.fontSize(14).font("Helvetica-Bold").text("Credential Subject");
        doc.moveDown(0.3);
        for (const [key, value] of Object.entries(subject)) {
          if (key === "id") continue; // handled separately if needed
          doc
            .fontSize(10)
            .font("Helvetica-Bold")
            .text(key + ": ", { continued: true });
          doc.font("Helvetica").text(String(value));
        }
      }

      // ----- QR code -----
      if (input.qrBuffer && input.qrBuffer.length > 0) {
        doc.moveDown(0.5);
        drawDivider(doc);
        doc.moveDown(0.5);
        doc.fontSize(11).font("Helvetica-Bold").text("Scan to Verify");
        doc.moveDown(0.3);
        doc.image(input.qrBuffer, { width: 150 });
      }

      // ----- Raw JSON -----
      doc.moveDown(0.5);
      drawDivider(doc);
      doc.moveDown(0.5);
      doc.fontSize(9).font("Helvetica-Bold").text("Machine-Readable Credential (JSON)");
      doc.moveDown(0.3);
      doc
        .fontSize(7)
        .font("Courier")
        .text(JSON.stringify(vc, null, 2), {
          lineGap: 1,
        });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function drawDivider(doc: PDFKit.PDFDocument): void {
  const y = doc.y;
  doc
    .moveTo(50, y)
    .lineTo(doc.page.width - 50, y)
    .strokeColor("#cccccc")
    .lineWidth(0.5)
    .stroke();
}

function extractTypes(vc: Record<string, unknown>): string[] {
  const raw = vc.type;
  if (Array.isArray(raw)) {
    return raw.filter((t) => t !== "VerifiableCredential").map(String);
  }
  if (typeof raw === "string" && raw !== "VerifiableCredential") {
    return [raw];
  }
  return [];
}

function extractIssuer(vc: Record<string, unknown>): string {
  const issuer = vc.issuer;
  if (typeof issuer === "string") return issuer;
  if (issuer && typeof issuer === "object") {
    const obj = issuer as Record<string, unknown>;
    if (typeof obj.name === "string" && typeof obj.id === "string") {
      return obj.name + " (" + obj.id + ")";
    }
    if (typeof obj.id === "string") return obj.id;
  }
  return "Unknown";
}

function extractSubject(vc: Record<string, unknown>): Record<string, unknown> | null {
  const sub = vc.credentialSubject;
  if (sub && typeof sub === "object" && !Array.isArray(sub)) {
    return sub as Record<string, unknown>;
  }
  return null;
}
