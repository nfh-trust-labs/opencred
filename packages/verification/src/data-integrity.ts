import { createPublicKey, type KeyObject } from "node:crypto";
import { verifyProof } from "@opencred/crypto";
import type { VerifiableCredential } from "@opencred/vc-core";
import type { DIDResolver } from "@opencred/did";
import { publicKeyFromMultibase } from "./key-utils.js";
import type { VerificationCheck } from "./types.js";

/**
 * Verify a Data Integrity proof on a VerifiableCredential.
 * Resolves the issuer's public key via DID resolution if a resolver is provided.
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

  if (proof.cryptosuite !== "ecdsa-rdfc-2019") {
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

  const result = await verifyProof(credential, { publicKey });
  if (result.verified) {
    return { name: "signature", passed: true };
  }
  return {
    name: "signature",
    passed: false,
    detail: result.error ?? "Signature verification failed",
  };
}

async function resolvePublicKeyFromVerificationMethod(
  verificationMethod: string,
  didResolver?: DIDResolver,
): Promise<KeyObject | undefined> {
  if (!didResolver) {
    return undefined;
  }

  const did = verificationMethod.split("#")[0];

  try {
    const resolution = await didResolver.resolve(did);
    if (!resolution.didDocument?.verificationMethod?.length) {
      return undefined;
    }

    const vmId = verificationMethod;
    const fragmentId = verificationMethod.includes("#")
      ? `#${verificationMethod.split("#")[1]}`
      : undefined;

    const vm = resolution.didDocument.verificationMethod.find(
      (m) => m.id === vmId || (fragmentId && m.id === fragmentId),
    );

    if (!vm) {
      return undefined;
    }

    if (vm.publicKeyMultibase) {
      const key = publicKeyFromMultibase(vm.publicKeyMultibase);
      return key ?? undefined;
    }

    if (vm.publicKeyJwk) {
      return createPublicKey({ key: vm.publicKeyJwk, format: "jwk" });
    }

    return undefined;
  } catch {
    return undefined;
  }
}
