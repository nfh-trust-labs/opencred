import { DIDResolutionError } from "@opencred/shared";
import type { DIDDocument, DIDResolutionResult, VerificationMethod } from "./types.js";
import type { DIDResolver } from "./resolver.js";
import { decodeBase58btc } from "./multibase.js";

const P256_MULTICODEC_VARINT_0 = 0x80;
const P256_MULTICODEC_VARINT_1 = 0x24;
const P256_COMPRESSED_KEY_LENGTH = 33;

export class DIDKeyResolver implements DIDResolver {
  async resolve(did: string): Promise<DIDResolutionResult> {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }

    const parts = did.split(":");
    if (parts.length !== 3 || parts[0] !== "did") {
      throw new DIDResolutionError(`Invalid DID format: expected did:<method>:<id>`);
    }

    if (parts[1] !== "key") {
      throw new DIDResolutionError(`Unsupported DID method: ${parts[1]}`);
    }

    const multibaseKey = parts[2];
    if (!multibaseKey || !multibaseKey.startsWith("z")) {
      throw new DIDResolutionError(
        "Only base58btc (z prefix) multibase encoding is supported",
      );
    }

    let decoded: Uint8Array;
    try {
      decoded = decodeBase58btc(multibaseKey.slice(1));
    } catch {
      throw new DIDResolutionError("Failed to decode multibase key");
    }

    if (
      decoded.length < 2 ||
      decoded[0] !== P256_MULTICODEC_VARINT_0 ||
      decoded[1] !== P256_MULTICODEC_VARINT_1
    ) {
      throw new DIDResolutionError(
        "Unsupported key type: only P-256 keys are supported",
      );
    }

    const publicKeyBytes = decoded.slice(2);
    if (publicKeyBytes.length !== P256_COMPRESSED_KEY_LENGTH) {
      throw new DIDResolutionError(
        `Invalid P-256 key length: expected ${P256_COMPRESSED_KEY_LENGTH} bytes, got ${publicKeyBytes.length}`,
      );
    }

    if (publicKeyBytes[0] !== 0x02 && publicKeyBytes[0] !== 0x03) {
      throw new DIDResolutionError(
        "Invalid P-256 compressed key: must start with 0x02 or 0x03",
      );
    }

    const verificationMethodId = `${did}#${multibaseKey}`;

    const verificationMethod: VerificationMethod = {
      id: verificationMethodId,
      type: "Multikey",
      controller: did,
      publicKeyMultibase: multibaseKey,
    };

    const didDocument: DIDDocument = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1",
      ],
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId],
      capabilityInvocation: [verificationMethodId],
      capabilityDelegation: [verificationMethodId],
    };

    return {
      didDocument,
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {},
    };
  }
}
