export type {
  DelegationCertificate,
  UnsignedDelegationCertificate,
  Delegator,
  Delegatee,
  DelegationScope,
  AuthorisationPath,
  DelegationCredentialStatus,
  DelegationStatus,
  CreateDelegationParams,
  ValidateDelegationResult,
  ValidateDelegationOptions,
  EmbedDelegationOptions,
  DelegatedCredentialProof,
  RegisterDelegationParams,
  ResolveDelegationParams,
} from "./types.js";

export { OPENCRED_DELEGATION_CONTEXT } from "./types.js";

export {
  createDelegationCertificate,
  validateDelegationCertificate,
  embedDelegation,
  isDelegationAuthorised,
  computeDelegationStatus,
} from "./certificate.js";

export {
  registerDelegation,
  resolveDelegation,
} from "./registry.js";
