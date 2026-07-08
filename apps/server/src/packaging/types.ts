/**
 * Packaging input types.
 *
 * These now live in the shared `@opencred/packaging` package (so the
 * desktop app and server agree on the contract). Re-exported here so the
 * server's internal imports (`./types.js`) keep working unchanged.
 */
export type { CredentialInput, PartialVerifiableCredential } from "@opencred/packaging";
