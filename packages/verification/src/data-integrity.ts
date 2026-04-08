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

    let vm = resolution.didDocument.verificationMethod.find(
      (m) => m.id === vmId || (fragmentId && m.id === fragmentId),
    );

    // Fallback: if the fragment is a base64url-encoded JWK (e.g. from the web UI),
    // it won't match the multibase fragment that did:key resolvers produce.
    // In that case, try to extract the public key directly from the fragment,
    // or fall back to the single VM in the document (did:key always has exactly one).
    if (!vm && fragmentId) {
      // Try decoding the fragment as a base64url JWK
      try {
        const decoded = fragmentId.slice(1); // remove leading '#'
        const jwkJson = JSON.parse(atob(decoded.replace(/-/g, "+").replace(/_/g, "/")));
        if (jwkJson.kty) {
          return createPublicKey({ key: jwkJson, format: "jwk" });
        }
      } catch {
        // Not a valid JWK fragment — fall through
      }

      // For did:key (single-key DIDs), use the only VM available
      if (did.startsWith("did:key:") && resolution.didDocument.verificationMethod.length === 1) {
        vm = resolution.didDocument.verificationMethod[0];
      }
    }

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
