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
  TRACEABILITY_V1_CONTEXT,
  OPEN_BADGES_V3_CONTEXT,
  OPENCRED_ELECTRICITY_V1_CONTEXT,
  OPENCRED_IMMUNIZATION_V1_CONTEXT,
  OPENCRED_PRESCRIPTION_V1_CONTEXT,
  OPENCRED_TEST_RESULT_V1_CONTEXT,
  OPENCRED_INSURANCE_POLICY_V1_CONTEXT,
  OPENCRED_FUNCTIONAL_IDENTITY_V1_CONTEXT,
  OPENCRED_EMPLOYMENT_OFFER_LETTER_V1_CONTEXT,
  OPENCRED_BUSINESS_ENTITY_V1_CONTEXT,
} from "./types.js";

export { generateInlineContext } from "./context-generator.js";

export { CredentialBuilder, isValidSubjectUri } from "./credential-builder.js";

export { ContextNotFoundError } from "./context-errors.js";

export {
  createDocumentLoader,
  getBundledContextUrls,
  setDefaultExtraContextResolver,
  getDefaultExtraContextResolver,
} from "./document-loader.js";

export type { JsonLdDocument, ExtraContextResolver } from "./document-loader.js";
