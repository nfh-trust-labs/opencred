import { createPublicKey, type KeyObject } from "node:crypto";
import { verifyProof, verifyEdDsaProof } from "@opencred/crypto";
import { ContextNotFoundError } from "@opencred/vc-core";
import type { VerifiableCredential } from "@opencred/vc-core";
import type { DIDResolver } from "@opencred/did";
import { publicKeyFromMultibase } from "./key-utils.js";
import type { VerificationCheck } from "./types.js";

const SUPPORTED_CRYPTOSUITES = ["ecdsa-rdfc-2019", "eddsa-rdfc-2022"] as const;

/**
 * Verify a Data Integrity proof on a VerifiableCredential.
 * Resolves the issuer's public key via DID resolution if a resolver is provided.
 *
 * SECURITY: The verification key MUST come from the resolved DID document. Any
 * data inside the credential (including the `verificationMethod` URL fragment)
 * is attacker-controlled and must NEVER be trusted as the source of the key.
 * If the resolved DID document does not contain a verification method whose
 * `id` matches `proof.verificationMethod`, verification fails.
 */
export async function verifyDataIntegrity(
  credential: VerifiableCredential,
  didResolver?: DIDResolver,
): Promise<VerificationCheck> {
  const proof = credential.proof;
  if (!proof) {
    return { name: "signature", passed: false, detail: "No proof found on credential" };
  }

  if (proof.type !== "DataIntegrityProof") {
    return { name: "signature", passed: false, detail: `Unsupported proof type: ${proof.type}` };
  }

  const cryptosuite = proof.cryptosuite as string;
  if (!SUPPORTED_CRYPTOSUITES.includes(cryptosuite as (typeof SUPPORTED_CRYPTOSUITES)[number])) {
    return {
      name: "signature",
      passed: false,
      detail: `Unsupported cryptosuite: ${String(proof.cryptosuite)}`,
    };
  }

  const publicKey = await resolvePublicKeyFromVerificationMethod(
    proof.verificationMethod,
    didResolver,
  );

  if (!publicKey) {
    return {
      name: "signature",
      passed: false,
      detail: "Unable to resolve public key from verificationMethod",
    };
  }

  // Route to appropriate verifier based on cryptosuite
  const verifyFn = cryptosuite === "eddsa-rdfc-2022" ? verifyEdDsaProof : verifyProof;
  try {
    const result = await verifyFn(credential, { publicKey });
    if (result.verified) {
      return { name: "signature", passed: true };
    }
    return {
      name: "signature",
      passed: false,
      detail: result.error ?? "Signature verification failed",
    };
  } catch (error) {
    if (error instanceof ContextNotFoundError) {
      return {
        name: "signature",
        passed: false,
        detail: `Missing JSON-LD context: ${error.contextUrl}. Import this context before verifying, or ask the issuer to use VC-JWT format.`,
      };
    }
    throw error;
  }
}

/**
 * Resolve the public key for a given verificationMethod.
 *
 * The lookup is strict: the verificationMethod string must split into a DID
 * (which is resolved) and a verification method whose `id` exactly matches
 * the credential's `verificationMethod`. If no such verification method exists
 * in the resolved DID document, this function returns `undefined` — there is
 * NO fallback to credential-controlled data.
 */
export async function resolvePublicKeyFromVerificationMethod(
  verificationMethod: string,
  didResolver?: DIDResolver,
): Promise<KeyObject | undefined> {
  if (!didResolver) {
    return undefined;
  }

  if (typeof verificationMethod !== "string" || verificationMethod.length === 0) {
    return undefined;
  }

  const did = verificationMethod.split("#")[0];
  if (!did) {
    return undefined;
  }

  let resolution;
  try {
    resolution = await didResolver.resolve(did);
  } catch {
    return undefined;
  }

  if (!resolution.didDocument?.verificationMethod?.length) {
    return undefined;
  }

  // Strict lookup: the verification method `id` published in the DID document
  // must exactly match the credential's `verificationMethod`. We also accept a
  // bare fragment match (`#fragment`) because some DID documents publish
  // verification methods with relative ids. We do NOT accept any other form of
  // matching, and we never decode or trust the fragment as key material.
  const fragmentId = verificationMethod.includes("#")
    ? `#${verificationMethod.split("#").slice(1).join("#")}`
    : undefined;

  const vm = resolution.didDocument.verificationMethod.find(
    (m) => m.id === verificationMethod || (fragmentId !== undefined && m.id === fragmentId),
  );

  if (!vm) {
    return undefined;
  }

  // Both publicKeyMultibase and publicKeyJwk come from the resolved DID
  // document, not from the credential, so they are trusted at this point.
  if (vm.publicKeyMultibase) {
    const key = publicKeyFromMultibase(vm.publicKeyMultibase);
    return key ?? undefined;
  }

  if (vm.publicKeyJwk) {
    try {
      return createPublicKey({ key: vm.publicKeyJwk, format: "jwk" });
    } catch {
      return undefined;
    }
  }

  return undefined;
}
