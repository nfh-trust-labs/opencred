/**
 * JSON-LD export for Verifiable Credentials.
 *
 * Exports the signed VC as a JSON-LD string with proper formatting.
 * Works completely offline.
 */

import type { VerifiableCredential } from "@opencred/vc-core";

/**
 * Export a VerifiableCredential as a formatted JSON-LD string.
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A pretty-printed JSON string.
 */
export function exportAsJsonLd(credential: VerifiableCredential): string {
  return JSON.stringify(credential, null, 2);
}

/**
 * Export a VerifiableCredential as a compact JSON string (no whitespace).
 *
 * @param credential - The signed VerifiableCredential.
 * @returns A compact JSON string.
 */
export function exportAsCompactJson(credential: VerifiableCredential): string {
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
