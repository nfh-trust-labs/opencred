/**
 * JSON-LD export for Verifiable Credentials.
 *
 * Exports the signed VC as a JSON-LD string with proper formatting.
 * Works completely offline.
 */

import type { VerifiableCredential } from "@opencred/vc-core";

/**
 * Wrap a compact `vc-jwt` / `sd-jwt-vc` token in a small JSON envelope
 * so the export file is still valid JSON (so it round-trips through
 * tooling that expects `application/json`) while preserving the original
 * token verbatim. The integrity guarantee lives in `credential` — re-wrap
 * is allowed because nothing inside `credential` is touched.
 */
function wrapCompactToken(token: string): { format: "vc-jwt" | "sd-jwt-vc"; credential: string } {
  return {
    format: token.includes("~") ? "sd-jwt-vc" : "vc-jwt",
    credential: token,
  };
}

/**
 * Export a credential as a formatted JSON string.
 *
 * For a JSON-LD `VerifiableCredential` (object input) this returns the
 * pretty-printed VC. For a compact-token credential (string input —
 * `vc-jwt` or `sd-jwt-vc`) it returns a `{ format, credential }`
 * envelope so the output is still valid JSON.
 *
 * @returns A pretty-printed JSON string.
 */
export function exportAsJson(credential: VerifiableCredential | string): string {
  if (typeof credential === "string") {
    return JSON.stringify(wrapCompactToken(credential), null, 2);
  }
  return JSON.stringify(credential, null, 2);
}

/**
 * Export a credential as a compact JSON string (no whitespace).
 *
 * Same envelope rules as `exportAsJson`.
 */
export function exportAsCompactJson(credential: VerifiableCredential | string): string {
  if (typeof credential === "string") {
    return JSON.stringify(wrapCompactToken(credential));
  }
  return JSON.stringify(credential);
}

/**
 * Parse and validate a JSON string as a VerifiableCredential.
 *
 * Performs basic structural validation (checks for required VC fields).
 *
 * @param json - The JSON string to parse.
 * @returns The parsed VerifiableCredential.
 * @throws if the JSON is invalid or missing required VC fields.
 */
export function parseCredentialJson(json: string): VerifiableCredential {
  const parsed = JSON.parse(json) as Record<string, unknown>;

  if (!parsed["@context"]) {
    throw new Error("Missing required field: @context");
  }
  if (!parsed["type"]) {
    throw new Error("Missing required field: type");
  }
  if (!parsed["issuer"]) {
    throw new Error("Missing required field: issuer");
  }
  if (!parsed["credentialSubject"]) {
    throw new Error("Missing required field: credentialSubject");
  }
  if (!parsed["proof"]) {
    throw new Error("Missing required field: proof");
  }

  return parsed as unknown as VerifiableCredential;
}
