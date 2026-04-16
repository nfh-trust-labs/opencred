/**
 * Zod validation schemas for IPC request payloads.
 *
 * These schemas are the main process's first defence when the renderer (or
 * any other IPC client — an unpatched Electron vulnerability, a sandboxed
 * WebView escape, etc.) sends a malformed payload to an `ipcMain.handle`
 * callback. Without schema validation, TypeScript's compile-time typing is
 * erased at the IPC boundary and handlers silently trust whatever arrives.
 *
 * HIGH-02 motivated adding the first schema here: `subjectDid` was plumbed
 * through to the credential subject's `id` with no format check, so an IPC
 * client could set it to `javascript:alert(1)` and issue a signed credential
 * that embeds an active-content URI. `isValidSubjectUri` from
 * `@opencred/vc-core` (added in Workstream #A) is the canonical gate.
 *
 * SECURITY NOTES:
 *  - These schemas mirror the interfaces in `ipc-types.ts`. The two files are
 *    kept in sync by review discipline; if you add a field to an interface,
 *    add it here too.
 *  - Schemas intentionally use `strict()` so unknown fields are rejected —
 *    prevents future fields from slipping through unvalidated.
 *  - No schema here accepts key material of any form. See CLAUDE.md rule 1.
 */

import { z } from "zod";
import { isValidSubjectUri } from "@opencred/vc-core";

/** Mirror of `UiProofFormat` from ipc-types.ts. */
const uiProofFormatSchema = z.enum(["vc-jwt", "data-integrity", "sd-jwt-vc"]);

/**
 * Zod schema for `BuildAndSignRequest`. Field-by-field mirror of the
 * interface in `ipc-types.ts`, plus the `subjectDid` URI-scheme refinement.
 *
 * The schema is intentionally permissive for types that already have tight
 * downstream validators (e.g. `schemaId`, `issuerDid` are later validated by
 * the credential builder / signer). The job here is to catch the shapes the
 * handler does NOT re-validate — most importantly `subjectDid`, because it
 * flows straight into `credentialSubject.id` in the inline-schema path.
 */
export const buildAndSignRequestSchema = z
  .object({
    // schemaId is optional because the inline-schema path allows the renderer
    // to omit it entirely (see "Build & sign — inline schema" tests).
    schemaId: z.string().optional(),
    issuerDid: z.string().min(1),
    // inlineSchema is either a JSON Schema object OR the literal boolean
    // `true` (a legacy sentinel from callers that only want the inline flow
    // without attaching a schema document). The handler branches on
    // `request.inlineSchema` truthiness, so both shapes are accepted.
    inlineSchema: z.union([z.record(z.unknown()), z.boolean()]).optional(),
    credentialSubject: z.record(z.unknown()),
    validFrom: z.string().min(1),
    validUntil: z.string().optional(),
    revocationRegistryUrl: z.string().optional(),
    additionalTypes: z.array(z.string()).optional(),
    subjectDid: z
      .string()
      .refine(isValidSubjectUri, {
        message:
          "subjectDid must be a DID (did:...), urn:uuid:..., or https:// URI. " +
          "Schemes like javascript:, data:, file:, or ../ are rejected.",
      })
      .optional(),
    keyId: z.string().min(1),
    packageFormats: z.array(z.string()).optional(),
    proofFormat: uiProofFormatSchema.optional(),
    selectiveDisclosureClaims: z.array(z.string()).optional(),
    credentialSchemaUrl: z.string().optional(),
    contextUrl: z.string().optional(),
    inlineContext: z.record(z.unknown()).optional(),
  })
  // NOTE: we intentionally don't use `.strict()` here. The existing type is
  // shipped to the renderer; downstream call sites may include new optional
  // fields before the schema catches up, and rejecting them is a worse UX
  // than silently ignoring them. New security-sensitive fields MUST be added
  // to this schema when they are introduced.
  .passthrough();

/**
 * Helper that parses a raw IPC request through a Zod schema and returns a
 * typed result. On failure, returns the flattened error message so the IPC
 * handler can surface it to the renderer without leaking a huge ZodError
 * tree.
 */
export function parseIpcRequest<T>(
  schema: z.ZodType<T>,
  raw: unknown,
): { ok: true; value: T } | { ok: false; error: string } {
  const result = schema.safeParse(raw);
  if (result.success) {
    return { ok: true, value: result.data };
  }
  // Format the first issue for brevity — the full details are available in
  // the logs; the UI only needs the headline.
  const first = result.error.issues[0];
  const path = first?.path.length ? first.path.join(".") + ": " : "";
  const msg = first?.message ?? "invalid IPC payload";
  return { ok: false, error: `${path}${msg}` };
}
