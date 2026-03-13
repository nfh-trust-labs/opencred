export {
  OPENCRED_KEY_ATTESTATION_V1_CONTEXT,
  type PublicKeyJwk,
  type IdentityVerificationMethod,
  type IdentityVerification,
  type KeyAttestationSubject,
  type KeyAttestationCredential,
  type UnsignedKeyAttestationCredential,
  type CreateKeyAttestationParams,
  type KeyAttestationValidationResult,
  type ValidateKeyAttestationOptions,
  type AttestationProof,
} from "./types.js";

export { createKeyAttestationVC } from "./builder.js";

export { validateKeyAttestation, isKeyAttestationCredential } from "./validator.js";

export {
  type DomainChallenge,
  type ChallengeDetails,
  type DomainVerificationResult,
  DomainChallengeStore,
  generateChallenge,
  verifyDnsTxtChallenge,
  verifyHttpChallenge,
  verifyDomainOwnership,
  isPrivateIP,
} from "./domain-verification.js";
