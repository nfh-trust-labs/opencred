/**
 * Brand-font registration for PDFKit.
 *
 * PDFKit ships only the 14 standard PDF fonts (Helvetica, Times, …). To
 * render the OpenCred editorial type system in the certificate we register
 * the bundled brand fonts (embedded as base64 in `font-data.ts`) on each
 * document. The logical names below are what the generator passes to
 * `doc.font(...)`.
 */

import {
  GeistRegular,
  GeistSemiBold,
  InstrumentSerifRegular,
  IBMPlexMonoRegular,
  IBMPlexMonoMedium,
} from "./font-data.js";

/** Logical font names used throughout the generator. */
export const FONT = {
  /** Geist — body copy and field values. */
  body: "OC-Body",
  /** Geist SemiBold — emphasis, issuer/subject names, sans headings. */
  bodySemibold: "OC-Body-SemiBold",
  /** Instrument Serif — the editorial display title. */
  display: "OC-Display",
  /** IBM Plex Mono — eyebrows, labels, IDs. */
  mono: "OC-Mono",
  /** IBM Plex Mono Medium — emphasised labels. */
  monoMedium: "OC-Mono-Medium",
} as const;

/**
 * Register the brand fonts on a PDFKit document. Must be called once, before
 * any `doc.font(...)` call that references a logical name above.
 */
export function registerBrandFonts(doc: PDFKit.PDFDocument): void {
  doc.registerFont(FONT.body, Buffer.from(GeistRegular, "base64"));
  doc.registerFont(FONT.bodySemibold, Buffer.from(GeistSemiBold, "base64"));
  doc.registerFont(FONT.display, Buffer.from(InstrumentSerifRegular, "base64"));
  doc.registerFont(FONT.mono, Buffer.from(IBMPlexMonoRegular, "base64"));
  doc.registerFont(FONT.monoMedium, Buffer.from(IBMPlexMonoMedium, "base64"));
}
