export type {
  ChallengeMethod,
  ChallengeStatus,
  DomainChallenge,
  ChallengeDetails,
  DomainVerificationResult,
} from "./types.js";

export {
  ChallengeStore,
  generateChallenge,
  verifyDomainOwnership,
} from "./challenge-manager.js";

export { verifyDnsTxtChallenge, DNS_TXT_PREFIX } from "./dns-verifier.js";

export { verifyHttpChallenge, WELL_KNOWN_PATH } from "./http-verifier.js";

export { isPrivateIP } from "./ssrf.js";
