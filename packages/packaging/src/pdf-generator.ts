/**
 * PDF certificate generator for Verifiable Credentials.
 *
 * Shared by the desktop app and the headless Docker server. Renders an
 * editorial, single-page certificate with the brand type system (Instrument
 * Serif display + Geist body + IBM Plex Mono labels) and an embedded QR code
 * that encodes the signed credential. Works completely offline.
 *
 * Layout:
 *  - Top brand rule + eyebrow + serif credential title + issuer line
 *  - QR "scan to verify" card (top-right)
 *  - Issued-to / validity metadata strip
 *  - Credential details (subject fields)
 *  - Digital signature metadata
 *  - Footer with verification note + generated timestamp
 *
 * SECURITY / COMPAT: the signed credential payload is embedded in the PDF
 * info dictionary under `PDF_CREDENTIAL_INFO_KEY` and read back by
 * `verifyPdf()` in `@opencred/verification`. That round-trip is load-bearing
 * — do not change the key or the payload encoding without coordinating with
 * the verification side. See the constant's doc comment.
 */

import PDFDocument from "pdfkit";
import type { VerifiableCredential } from "@opencred/vc-core";
import type { TemplateCustomization } from "@opencred/templates";
import { compressCredentialForQr, generateQrBuffer } from "./qr-generator.js";
import type { CredentialInput, PartialVerifiableCredential, PackagingLogger } from "./types.js";
import { registerBrandFonts, FONT } from "./fonts.js";

/**
 * PDF info-dictionary key that holds the embedded credential.
 *
 * Read by `verifyPdf()` in `@opencred/verification`. The value is the same
 * bare PixelPass-compressed payload that's printed into the QR on the
 * certificate page (or, for compact-token issuance, the raw vc-jwt /
 * sd-jwt-vc token).
 *
 * **What's load-bearing.** The PDF spec (ISO 32000-1) allows arbitrary
 * keys in the info dictionary, but the round-trip here actually relies on
 * a *runtime* property of PDFKit: `PDFDocument.end()` iterates own
 * enumerable string properties of `doc.info` and writes each one into the
 * output info dict. That is not a documented public API, so a future
 * pdfkit upgrade could in principle drop arbitrary keys silently — which
 * would make verification fail on freshly issued PDFs. The round-trip
 * tests exist to catch exactly that regression.
 *
 * Changing this key name is a backwards-incompatible change; coordinate
 * with the verification side.
 */
export const PDF_CREDENTIAL_INFO_KEY = "OpenCredCredential";

/**
 * Options for PDF generation.
 */
export interface PdfOptions {
  customization?: TemplateCustomization;
  /**
   * If set, the QR code embedded in the PDF encodes this string verbatim
   * (typically the original compact `vc-jwt` / `sd-jwt-vc` token) rather
   * than a PixelPass-compressed JSON-LD payload built from `credential`.
   * The `credential` argument is still used for the page layout.
   */
  qrPayloadOverride?: string;
  /** Optional structured logger for diagnostics. Defaults to no-op. */
  logger?: PackagingLogger;
}

// ---------------------------------------------------------------------------
// Layout + palette
// ---------------------------------------------------------------------------

const PAGE_W = 595.28; // A4
const PAGE_H = 841.89;
const MARGIN = 54;
const LEFT = MARGIN;
const RIGHT = PAGE_W - MARGIN;
const CONTENT_W = RIGHT - LEFT;
const QR_CARD_W = 132;
const QR_SIZE = 104;
const BOTTOM_LIMIT = PAGE_H - MARGIN; // keep the footer above the page edge

// Editorial brand palette (defaults; overridable via customization).
const ACCENT = "#0057FF";
const INK = "#1a1a1a";
const BODY = "#3f3f3f";
const LABEL = "#7a7a7a";
const MUTED = "#9a9a9a";
const HAIRLINE = "#e3e0da";
const CARD_BG = "#f7f5f1";

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

function getCredentialTitle(credential: PartialVerifiableCredential): string {
  const types = Array.isArray(credential.type) ? credential.type : [String(credential.type)];
  const meaningful = types.filter((t) => t !== "VerifiableCredential");
  if (meaningful.length > 0) {
    return meaningful.map((t) => t.replace(/([a-z])([A-Z])/g, "$1 $2")).join(", ");
  }
  return "Verifiable Credential";
}

/**
 * Best-effort issuer-display string. Tolerant of `issuer` being a string,
 * an object with `id`, or absent (synthetic VC shape from a compact JWT).
 */
function getIssuerDisplay(credential: PartialVerifiableCredential): string {
  const issuer = (credential as { issuer?: unknown }).issuer;
  if (typeof issuer === "string") return issuer;
  if (issuer && typeof issuer === "object" && "id" in issuer) {
    const id = (issuer as { id?: unknown }).id;
    if (typeof id === "string") return id;
  }
  return "(issuer not provided)";
}

const NOOP_LOGGER: PackagingLogger = { warn: () => {}, debug: () => {} };

/**
 * Generate the QR code that gets embedded into the PDF. Returns `null`
 * when QR generation fails — the PDF still renders, with the
 * "credential too large for QR" footnote in place of the QR.
 */
async function generateQrPngBuffer(
  qrInput: CredentialInput,
  credentialId: string | undefined,
  logger: PackagingLogger,
): Promise<Buffer | null> {
  try {
    return await generateQrBuffer(qrInput);
  } catch (err) {
    logger.warn(
      {
        credentialId,
        err: err instanceof Error ? err.message : String(err),
        inputKind: qrInput.kind,
      },
      "QR omitted from PDF certificate",
    );
    return null;
  }
}

// ---------------------------------------------------------------------------
// PDF generation
// ---------------------------------------------------------------------------

/**
 * Generate an editorial PDF certificate from a VerifiableCredential.
 *
 * The PDF includes a QR code encoding the credential. If the credential
 * is too large for a QR code, the QR is omitted and a note is shown.
 */
export async function generatePdf(
  credential: PartialVerifiableCredential,
  options?: PdfOptions,
): Promise<Buffer> {
  const logger = options?.logger ?? NOOP_LOGGER;

  // QR payload: verbatim compact token if overridden, else PixelPass VC.
  const qrInput: CredentialInput = options?.qrPayloadOverride
    ? { kind: "compact-token", token: options.qrPayloadOverride }
    : { kind: "vc", credential: credential as unknown as VerifiableCredential };
  const qrBuffer = await generateQrPngBuffer(
    qrInput,
    typeof credential.id === "string" ? credential.id : undefined,
    logger,
  );

  // Payload embedded in the info dict — mirrors exactly what the QR encodes.
  const embeddedCredential =
    qrInput.kind === "compact-token" ? qrInput.token : compressCredentialForQr(qrInput.credential);

  const c = options?.customization;
  const accent = c?.primaryColor ?? ACCENT;
  const sectionColor = c?.secondaryColor ?? accent;
  const bgColor = c?.backgroundColor ?? "#ffffff";
  const textColor = c?.textColor ?? INK;
  const labelColor = c?.labelColor ?? LABEL;
  const issuerDisplay = c?.issuerDisplayName ?? getIssuerDisplay(credential);
  const footerText =
    c?.footerText ?? "This credential is digitally signed and can be independently verified.";
  const logoUri = c?.logoDataUri;
  const logoW = c?.logoWidth ?? 56;
  const logoH = c?.logoHeight ?? 56;
  const sealUri = c?.sealDataUri;

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: "A4",
        margin: MARGIN,
        info: {
          Title: `${getCredentialTitle(credential)} Certificate`,
          Author: "OpenCred",
          Subject: `Credential: ${credential.id}`,
          Creator: "OpenCred",
        },
      });

      registerBrandFonts(doc);

      // Load-bearing: embed the credential payload for verifyPdf().
      (doc.info as unknown as Record<string, string>)[PDF_CREDENTIAL_INFO_KEY] = embeddedCredential;

      const buffers: Buffer[] = [];
      doc.on("data", (chunk: Buffer) => buffers.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(buffers)));
      doc.on("error", reject);

      // -- shared drawing helpers (closures over doc) --------------------

      const hairline = (y: number) => {
        doc.save().moveTo(LEFT, y).lineTo(RIGHT, y).lineWidth(0.75).strokeColor(HAIRLINE).stroke().restore();
      };

      /** Section heading: accent mono eyebrow with a trailing hairline. */
      const sectionHeading = (title: string) => {
        if (doc.y > BOTTOM_LIMIT - 120) doc.addPage();
        doc.moveDown(0.7);
        const y = doc.y;
        doc
          .font(FONT.monoMedium)
          .fontSize(8)
          .fillColor(sectionColor)
          .text(title.toUpperCase(), LEFT, y, { characterSpacing: 1.2, lineBreak: false });
        const textW = doc.widthOfString(title.toUpperCase(), { characterSpacing: 1.2 });
        doc
          .save()
          .moveTo(LEFT + textW + 10, y + 5)
          .lineTo(RIGHT, y + 5)
          .lineWidth(0.75)
          .strokeColor(HAIRLINE)
          .stroke()
          .restore();
        doc.y = y + 18;
      };

      /** Label/value row. Mono uppercase label column + value column. */
      const field = (
        label: string,
        value: string,
        opts: { labelWidth?: number; valueFont?: string; valueColor?: string; indent?: number } = {},
      ) => {
        const indent = opts.indent ?? 0;
        const labelWidth = opts.labelWidth ?? 150;
        const x = LEFT + indent;
        const y = doc.y;
        const valueX = x + labelWidth;
        const valueW = RIGHT - valueX;
        doc
          .font(FONT.mono)
          .fontSize(7.5)
          .fillColor(labelColor)
          .text(label.toUpperCase(), x, y + 1.5, {
            width: labelWidth - 10,
            characterSpacing: 0.4,
            lineBreak: false,
            ellipsis: true,
          });
        doc
          .font(opts.valueFont ?? FONT.body)
          .fontSize(9.5)
          .fillColor(opts.valueColor ?? textColor)
          .text(value || "—", valueX, y, { width: valueW });
        doc.y = Math.max(doc.y, y + 15);
      };

      // -- background + top brand rule -----------------------------------
      if (bgColor !== "#ffffff") doc.rect(0, 0, PAGE_W, PAGE_H).fill(bgColor);
      doc.save().rect(0, 0, PAGE_W, 5).fill(accent).restore();

      // -- QR card (top-right) -------------------------------------------
      const headerTop = 78;
      let qrCardBottom = headerTop;
      if (qrBuffer) {
        const cardX = RIGHT - QR_CARD_W;
        const cardY = headerTop;
        const cardH = QR_SIZE + 34;
        doc
          .save()
          .roundedRect(cardX, cardY, QR_CARD_W, cardH, 8)
          .lineWidth(1)
          .fillAndStroke(CARD_BG, HAIRLINE)
          .restore();
        const qrX = cardX + (QR_CARD_W - QR_SIZE) / 2;
        doc.image(qrBuffer, qrX, cardY + 10, { width: QR_SIZE, height: QR_SIZE });
        doc
          .font(FONT.mono)
          .fontSize(6.5)
          .fillColor(MUTED)
          .text("SCAN TO VERIFY", cardX, cardY + QR_SIZE + 17, {
            width: QR_CARD_W,
            align: "center",
            characterSpacing: 1,
          });
        qrCardBottom = cardY + cardH;
      }

      // -- header (left) --------------------------------------------------
      const headerW = qrBuffer ? CONTENT_W - QR_CARD_W - 24 : CONTENT_W;
      doc.y = headerTop;

      if (logoUri) {
        try {
          const logoBuffer = Buffer.from(logoUri.split(",")[1], "base64");
          doc.image(logoBuffer, LEFT, doc.y, { fit: [logoW, logoH] });
          doc.y += logoH + 12;
        } catch (err) {
          logger.debug(
            { err: err instanceof Error ? err.message : String(err) },
            "Logo image render failed; logo omitted from PDF",
          );
        }
      }

      doc
        .font(FONT.mono)
        .fontSize(8)
        .fillColor(accent)
        .text("VERIFIABLE CREDENTIAL", LEFT, doc.y, {
          width: headerW,
          characterSpacing: 1.8,
        });
      doc.moveDown(0.4);
      doc
        .font(FONT.display)
        .fontSize(29)
        .fillColor(textColor)
        .text(getCredentialTitle(credential), LEFT, doc.y, { width: headerW });
      doc.moveDown(0.35);
      doc
        .font(FONT.body)
        .fontSize(10)
        .fillColor(BODY)
        .text("Issued by ", LEFT, doc.y, { width: headerW, continued: true })
        .font(FONT.bodySemibold)
        .fillColor(textColor)
        .text(issuerDisplay);

      // Move below whichever column is taller, then a divider.
      doc.y = Math.max(doc.y, qrCardBottom) + 16;
      hairline(doc.y);
      doc.y += 16;

      // -- metadata strip: issued-to / validity --------------------------
      const subject = credential.credentialSubject;
      const metaY = doc.y;
      const colW = (CONTENT_W - 24) / 2;
      const metaLabel = (t: string, x: number) =>
        doc
          .font(FONT.mono)
          .fontSize(7)
          .fillColor(labelColor)
          .text(t.toUpperCase(), x, metaY, { width: colW, characterSpacing: 0.8 });
      const validFromStr =
        typeof credential.validFrom === "string" ? formatDate(credential.validFrom) : "(not specified)";
      const validUntilStr =
        typeof credential.validUntil === "string" ? formatDate(credential.validUntil) : "No expiration";

      if (subject.id) {
        metaLabel("Issued to", LEFT);
        metaLabel("Validity", LEFT + colW + 24);
        doc.y = metaY + 11;
        const valY = doc.y;
        doc
          .font(FONT.body)
          .fontSize(9.5)
          .fillColor(textColor)
          .text(String(subject.id), LEFT, valY, { width: colW });
        const afterLeft = doc.y;
        doc
          .font(FONT.body)
          .fontSize(9.5)
          .fillColor(textColor)
          .text(`${validFromStr} — ${validUntilStr}`, LEFT + colW + 24, valY, { width: colW });
        doc.y = Math.max(afterLeft, doc.y) + 6;
      } else {
        metaLabel("Validity", LEFT);
        doc.y = metaY + 11;
        doc
          .font(FONT.body)
          .fontSize(9.5)
          .fillColor(textColor)
          .text(`${validFromStr} — ${validUntilStr}`, LEFT, doc.y, { width: CONTENT_W });
        doc.y += 6;
      }

      // -- credential details --------------------------------------------
      const subjectEntries = Object.entries(subject).filter(([key]) => key !== "id");
      if (subjectEntries.length > 0) {
        sectionHeading("Credential Details");
        for (const [key, value] of subjectEntries) {
          if (typeof value === "object" && value !== null) {
            field(formatLabel(key), "");
            for (const [subKey, subValue] of Object.entries(value as Record<string, unknown>)) {
              field(formatLabel(subKey), String(subValue ?? ""), { indent: 14, labelWidth: 136 });
            }
          } else {
            field(formatLabel(key), String(value ?? ""));
          }
        }
      }

      // -- digital signature ---------------------------------------------
      // Two shapes flow through: a real Data Integrity VC (proof fields
      // mandatory — warn + "(unknown)" if missing) and a synthetic shape
      // from a compact JWT/SD-JWT (caller set qrPayloadOverride — missing
      // fields expected, skip silently).
      sectionHeading("Digital Signature");
      const isSyntheticProof = options?.qrPayloadOverride !== undefined;
      const proof =
        (credential.proof as Record<string, unknown> | undefined) ?? ({} as Record<string, unknown>);
      const asString = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
      const credentialId = typeof credential.id === "string" ? credential.id : undefined;
      const warnIfReal = (f: string) => {
        if (!isSyntheticProof) {
          logger.warn(
            { credentialId, field: f },
            "Data Integrity proof field missing — rendered as (unknown) on PDF",
          );
        }
      };
      const sigField = (label: string, value: string) =>
        field(label, value, { valueFont: FONT.mono, valueColor: BODY });

      const proofType = asString(proof["type"]);
      if (proofType) sigField("Proof Type", proofType);
      else {
        warnIfReal("type");
        sigField("Proof Type", "(unknown)");
      }
      const proofCryptosuite = asString(proof["cryptosuite"]);
      if (proofCryptosuite) sigField("Cryptosuite", proofCryptosuite);
      else if (!isSyntheticProof) {
        warnIfReal("cryptosuite");
        sigField("Cryptosuite", "(unknown)");
      }
      const proofCreated = asString(proof["created"]);
      if (proofCreated) sigField("Created", formatDate(proofCreated));
      else if (!isSyntheticProof) {
        warnIfReal("created");
        sigField("Created", "(unknown)");
      }
      const proofVm = asString(proof["verificationMethod"]);
      if (proofVm) sigField("Verification Method", proofVm);
      else if (!isSyntheticProof) {
        warnIfReal("verificationMethod");
        sigField("Verification Method", "(unknown)");
      }
      if (Array.isArray(proof["x5c"]) && (proof["x5c"] as unknown[]).length > 0) {
        sigField("Certificate Chain", `${(proof["x5c"] as unknown[]).length} certificate(s) embedded`);
      }

      // -- seal (optional, bottom-right) ---------------------------------
      if (sealUri) {
        try {
          const sealBuffer = Buffer.from(sealUri.split(",")[1], "base64");
          doc.image(sealBuffer, RIGHT - 76, doc.y + 4, { fit: [72, 72] });
        } catch (err) {
          logger.debug(
            { err: err instanceof Error ? err.message : String(err) },
            "Seal image render failed; seal omitted from PDF",
          );
        }
      }

      // -- footer (pinned near the bottom) -------------------------------
      const footerY = Math.max(doc.y + 24, BOTTOM_LIMIT - 46);
      hairline(footerY);
      let fy = footerY + 10;
      if (!qrBuffer) {
        doc
          .font(FONT.body)
          .fontSize(7.5)
          .fillColor(MUTED)
          .text(
            "This credential is too large for a QR code. Use the JSON export to share the full data.",
            LEFT,
            fy,
            { width: CONTENT_W, align: "center" },
          );
        fy = doc.y + 2;
      }
      if (footerText) {
        doc
          .font(FONT.body)
          .fontSize(8)
          .fillColor(MUTED)
          .text(footerText, LEFT, fy, { width: CONTENT_W, align: "center" });
        fy = doc.y + 1;
      }
      doc
        .font(FONT.mono)
        .fontSize(6.5)
        .fillColor(MUTED)
        .text(
          `SECURED BY OPENCRED   ·   GENERATED ${formatDate(new Date().toISOString()).toUpperCase()}`,
          LEFT,
          fy,
          { width: CONTENT_W, align: "center", characterSpacing: 0.8 },
        );

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
}
