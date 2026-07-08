/**
 * Verification instrumentation — wraps verification components so each
 * operation emits a span.
 *
 * Spans emitted via this module:
 *   - `verify.did_resolve` — every DIDResolver.resolve() call
 *
 * Spans emitted directly by `apps/server/src/routes/credentials.ts`:
 *   - `verify.credential` — wraps the top-level verifyCredential /
 *     verifyPdf invocation, with `verify.format` + `verify.code`
 *     attributes and an event per check.
 *
 * Schema-validation spans (`verify.schema_validate`) and CORD-anchor
 * spans (`verify.cord_anchor_check`) live where their checks actually
 * run — see `packages/verification/src/checks.ts`. We do NOT wrap
 * those packages here because the engine modules are reused by the
 * desktop app, and tracing should remain a server-side concern.
 *
 * SECURITY (CLAUDE.md):
 *   - `did_resolve` carries only the DID string. DID is by definition
 *     public, but we cap it at 256 chars to defend against a hostile
 *     caller smuggling unbounded data into the attribute.
 */

import type { DIDResolver } from "@opencred/did";

import { runInSpan } from "./span-helpers.js";

/**
 * Trim an attribute value to a fixed maximum length. Returns the
 * original string when within bounds, otherwise truncates and appends
 * a marker so the trim is obvious in a trace UI.
 */
function clampAttr(value: string, maxLen = 256): string {
  if (value.length <= maxLen) return value;
  return `${value.slice(0, maxLen - 1)}…`;
}

/**
 * Wrap a DID resolver so every `resolve()` call emits a
 * `verify.did_resolve` span. The DID itself is the only attribute —
 * it's part of the credential's public envelope and is meaningful for
 * operators tracking down "why is this issuer's verification slow".
 */
export function wrapDidResolverWithTracing(resolver: DIDResolver): DIDResolver {
  return {
    resolve(did: string) {
      const method = did.startsWith("did:")
        ? (did.slice(4).split(":", 1)[0] ?? "unknown")
        : "unknown";
      return runInSpan("verify.did_resolve", { "did.method": method, did: clampAttr(did) }, () =>
        resolver.resolve(did),
      );
    },
  };
}
