/**
 * parseJsonBody — read and JSON-parse a Hono request body, mapping the
 * underlying SyntaxError to a 400 INVALID_JSON response.
 *
 * Rationale:
 *   The previous implementation lived in the global error handler and
 *   inspected `err.stack` for "hono/dist/request.js" to distinguish
 *   "request body wasn't JSON" from "a SyntaxError leaked from
 *   somewhere else in the handler." That heuristic was fragile to
 *   Hono internal-path renames (silently regresses to 500 when Hono
 *   reorganises its dist tree).
 *
 *   Wrapping `c.req.json()` at the route layer makes the boundary
 *   explicit: if it throws, the body is malformed; everything else
 *   stays on the existing 500/INTERNAL_ERROR path.
 *
 * What this catches:
 *   - SyntaxError raised by `c.req.json()`'s underlying JSON.parse
 *     when the request body is not valid JSON.
 *
 * What this DOES NOT catch (intentionally):
 *   - JSON.parse calls inside route handlers (e.g. the verify route's
 *     `JSON.parse(parsed.credential)` for inline JSON credentials).
 *     Those are server bugs or unexpected input shapes, not "the
 *     request body isn't JSON," and should keep their existing 500
 *     path so they're loud in logs.
 *
 * Security invariants:
 *   - V8 / JSC JSON parser errors contain a position number but never
 *     echo body bytes. If a future engine changes that,
 *     `OpenCredError.toJSON()` scrubs the message via
 *     `sanitizeErrorMessage` (PEM blocks, paths, base64) before reaching
 *     the wire.
 *   - Body length is bounded by the bodyLimit middleware in
 *     `index.ts`, so this helper does not need its own length cap.
 */

import type { Context } from "hono";
import { MalformedJsonError } from "@opencred/shared";

export async function parseJsonBody(c: Context): Promise<unknown> {
  try {
    return await c.req.json();
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new MalformedJsonError(`Request body is not valid JSON: ${detail}`);
  }
}
