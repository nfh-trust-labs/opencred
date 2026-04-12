/**
 * Credential packaging endpoint.
 *
 * POST /credentials/package — package a signed VC into PDF, QR, JSON formats
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

const packaging = new Hono();

const packageRequestSchema = z.object({
  credential: z.record(z.unknown()),
  formats: z
    .array(z.enum(["qr-png", "qr-svg", "pdf", "json", "json-compact"]))
    .default(["json"]),
  customization: customizationSchema,
});

packaging.post("/credentials/package", async (c) => {
  const body = await c.req.json();
  // SECURITY: defense-in-depth — no route accepts key material. See CLAUDE.md rule 1.
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
