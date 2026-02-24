export type {
  ContextEntry,
  CredentialSchema,
  CredentialStatus,
  CredentialSubject,
  Issuer,
  IssuerObject,
  Proof,
  UnsignedCredential,
  VerifiableCredential,
} from "./types.js";

export {
  W3C_CREDENTIALS_V2_CONTEXT,
  DATA_INTEGRITY_V1_CONTEXT,
  OPENCRED_DELEGATION_V1_CONTEXT,
} from "./types.js";

export { CredentialBuilder } from "./credential-builder.js";

export { createDocumentLoader, getBundledContextUrls } from "./document-loader.js";

export type { JsonLdDocument } from "./document-loader.js";
