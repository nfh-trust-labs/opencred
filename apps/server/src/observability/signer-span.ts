/**
 * Signer instrumentation — wraps a {@link Signer} so each `sign()` call
 * produces a `signer.sign` span.
 *
 * The Signer interface ({@link import("@opencred/signing").Signer}) is
 * already-narrowed to "metadata + sign(data: Uint8Array)". The wrapper
 * preserves the surface (so callers can substitute it transparently)
 * and adds a span around the `sign()` call with metadata-only
 * attributes.
 *
 * SECURITY (CLAUDE.md):
 *   - `dataToSign` is NEVER written to the span. Only its byte length,
 *     the signing algorithm, the signer's opaque fingerprint, and the
 *     signer kind (software / pkcs11 / os-cert / cloud-hsm).
 *   - The signature bytes are NEVER written to the span. Only their
 *     length is captured on success.
 *   - Exception messages from the underlying signer pass through
 *     `recordException`, which serialises `err.message` only — never
 *     `err.cause` private data.
 */

import type { Signer } from "@opencred/signing";

import { runInSpan } from "./span-helpers.js";

/**
 * The "kind" of signer for span attributes. Distinct from
 * `Signer.type` because every cloud-HSM signer in
 * `apps/server/src/signing/cloud-hsm/*` self-reports as
 * `type: "software"` (since the produced signatures are raw EC and
 * the post-processing is identical). For operator-facing dashboards
 * we want to distinguish "AWS KMS" from "local PEM" even when both
 * report the same Signer.type.
 */
export type SignerKind = "software" | "pkcs11" | "os-cert" | "cloud-hsm-aws" | "cloud-hsm-azure" | "cloud-hsm-gcp";

/**
 * Wrap a Signer so every `sign()` call is instrumented with a
 * `signer.sign` span. Returns a new Signer; the original is not
 * mutated — Signer instances passed in via the singleton path are
 * shared with non-tracing call sites (e.g. desktop IPC tests).
 *
 * When tracing is disabled (`OPENCRED_OTEL_ENABLED=false`), the
 * underlying `runInSpan` resolves to the no-op tracer and the
 * overhead is roughly one extra function call per signature.
 */
export function wrapSignerWithTracing(signer: Signer, kind: SignerKind): Signer {
  return {
    id: signer.id,
    algorithm: signer.algorithm,
    type: signer.type,
    metadata: signer.metadata,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return runInSpan(
        "signer.sign",
        {
          "signer.algorithm": signer.algorithm,
          "signer.kind": kind,
          // Fingerprint identifies the key without exposing it. Length
          // captures input size for capacity planning.
          "signer.fingerprint": signer.metadata.fingerprint,
          "signer.input_bytes": data.byteLength,
        },
        async (span) => {
          const sig = await signer.sign(data);
          // Output size is metadata; signature bytes themselves are NOT
          // recorded. CLAUDE.md rule 2 — never log key material or
          // signing buffers.
          span.setAttribute("signer.signature_bytes", sig.byteLength);
          return sig;
        },
      );
    },
  };
}
