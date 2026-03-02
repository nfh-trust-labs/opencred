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
  revokeDelegation,
  isDelegationRevoked,
} from "./registry.js";

export { validateDelegationChain, validateDelegateeMatchesSigningKey } from "./chain.js";

export type { ChainValidationResult, ChainValidationOptions, DelegationResolver, RevocationCheckStatus } from "./chain.js";
