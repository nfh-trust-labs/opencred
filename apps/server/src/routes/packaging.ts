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
import { packageCredential } from "../packaging/packager.js";
import type { PackageFormat } from "../packaging/packager.js";

const packaging = new Hono();

const packageRequestSchema = z.object({
  credential: z.record(z.unknown()),
  formats: z
    .array(z.enum(["qr-png", "qr-svg", "pdf", "json-ld", "json-compact"]))
    .default(["json-ld"]),
});

packaging.post("/credentials/package", async (c) => {
  const body = await c.req.json();
  const parsed = packageRequestSchema.parse(body);

  const credential = parsed.credential as unknown as Parameters<typeof packageCredential>[0];
  const formats = parsed.formats as PackageFormat[];

  const result = await packageCredential(credential, formats);

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
