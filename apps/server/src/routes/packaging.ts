/**
 * Credential packaging endpoint.
 *
 * POST /credentials/package — package a signed credential into PDF, QR,
 * JSON formats.
 *
 * Accepts the credential in either of two forms:
 *
 *   1. **JSON object** — a JSON-LD `VerifiableCredential` (typically
 *      what `proofFormat: "data-integrity"` returns from
 *      `/credentials/issue`).
 *   2. **String** — a compact `vc-jwt` or `sd-jwt-vc` token (what
 *      `proofFormat: "vc-jwt"` / `"sd-jwt-vc"` return). The token is
 *      embedded verbatim into the QR code; its payload drives the PDF
 *      certificate layout. No signature verification is performed —
 *      packaging is a rendering operation, and the integrity guarantee
 *      lives in the original token, which is preserved byte-for-byte
 *      everywhere it matters (QR + JSON envelope).
 *
 * Returns base64-encoded outputs for binary formats (PDF, QR PNG) and
 * string outputs for text formats (SVG, JSON).
 */

import { Hono } from "hono";
import { z } from "zod";
import type { TemplateCustomization } from "@opencred/templates";
import { packageCredential } from "../packaging/packager.js";
import type { PackageFormat } from "../packaging/packager.js";
import { rejectKeyMaterial, customizationSchema } from "./credentials.js";
import { parseJsonBody } from "../middleware/parse-json.js";

const packaging = new Hono();

// `credential` is one of:
//   - a JSON object → JSON-LD VerifiableCredential
//   - a string      → compact vc-jwt / sd-jwt-vc token
// The `min(1)` on the string variant rejects an empty string (which
// would otherwise crash the JWT decoder later).
const packageRequestSchema = z.object({
  credential: z.union([z.record(z.unknown()), z.string().min(1)]),
  formats: z.array(z.enum(["qr-png", "qr-svg", "pdf", "json", "json-compact"])).default(["json"]),
  customization: customizationSchema,
});

packaging.post("/credentials/package", async (c) => {
  const body = await parseJsonBody(c);
  // SECURITY: defense-in-depth — no route accepts key material. See CLAUDE.md rule 1.
  // The recursive walk inspects both object trees and any string field
  // values. A compact JWT is base64url segments separated by `.` — no
  // PEM headers — so this guard does not false-positive on legitimate
  // compact-token input.
  rejectKeyMaterial(body);
  const parsed = packageRequestSchema.parse(body);

  const credential = parsed.credential as unknown as Parameters<typeof packageCredential>[0];
  const formats = parsed.formats as PackageFormat[];
  const customization = parsed.customization as TemplateCustomization | undefined;

  const result = await packageCredential(credential, formats, { customization });

  const outputs = result.outputs.map((output) => ({
    format: output.format,
    data: Buffer.isBuffer(output.data) ? output.data.toString("base64") : output.data,
    mimeType: output.mimeType,
    suggestedFileName: output.suggestedFileName,
    encoding: Buffer.isBuffer(output.data) ? ("base64" as const) : ("utf-8" as const),
  }));

  return c.json({ outputs, errors: result.errors });
});

export { packaging };
