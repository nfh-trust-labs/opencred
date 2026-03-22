/**
 * AWS KMS Signer — implements the Signer interface using AWS KMS SignCommand.
 *
 * Config from env: OPENCRED_KMS_KEY_ARN
 *
 * SECURITY INVARIANTS:
 *  - The private key never leaves AWS KMS.
 *  - Key material is NEVER logged — only the key ARN and algorithm.
 *  - Sign operations send a digest, not raw plaintext.
 */

import { createPublicKey } from "node:crypto";
import {
  KMSClient,
  SignCommand,
  DescribeKeyCommand,
  GetPublicKeyCommand,
  type KeyMetadata,
  type SigningAlgorithmSpec,
} from "@aws-sdk/client-kms";
import type { SigningAlgorithm } from "@opencred/crypto";
import { sha256, sha384 } from "@opencred/crypto";
import type { Signer, SignerMetadata } from "@opencred/signing";
import { computeFingerprint, deriveDidKeyIdFromPublicKey } from "@opencred/signing";

/**
 * Map KMS key spec to OpenCred SigningAlgorithm.
 */
function kmsKeySpecToAlgorithm(spec: string): SigningAlgorithm {
  switch (spec) {
    case "ECC_NIST_P256":
      return "P-256";
    case "ECC_NIST_P384":
      return "P-384";
    case "RSA_2048":
      return "RSA-2048";
    case "RSA_3072":
      return "RSA-3072";
    case "RSA_4096":
      return "RSA-4096";
    default:
      throw new Error(`Unsupported KMS key spec: ${spec}`);
  }
}

/**
 * Map OpenCred algorithm to KMS signing algorithm identifier.
 */
function algorithmToKmsSigningAlg(alg: SigningAlgorithm): SigningAlgorithmSpec {
  switch (alg) {
    case "P-256":
      return "ECDSA_SHA_256";
    case "P-384":
      return "ECDSA_SHA_384";
    case "RSA-2048":
    case "RSA-3072":
    case "RSA-4096":
      return "RSASSA_PSS_SHA_256";
    default:
      throw new Error(`Unsupported algorithm for KMS: ${alg}`);
  }
}

/**
 * Create a Signer backed by AWS KMS.
 */
export async function createAwsKmsSigner(keyArn: string): Promise<Signer> {
  const client = new KMSClient({});

  // Describe the key to determine algorithm
  const describeRes = await client.send(new DescribeKeyCommand({ KeyId: keyArn }));
  const keyMeta: KeyMetadata = describeRes.KeyMetadata!;
  const algorithm = kmsKeySpecToAlgorithm(keyMeta.KeySpec!);

  // Get public key for DID derivation and fingerprint
  const pubKeyRes = await client.send(new GetPublicKeyCommand({ KeyId: keyArn }));
  const publicKeyDer = pubKeyRes.PublicKey!;
  const publicKeyObj = createPublicKey({
    key: Buffer.from(publicKeyDer),
    format: "der",
    type: "spki",
  });

  const fingerprint = computeFingerprint(publicKeyObj);
  const id = deriveDidKeyIdFromPublicKey(publicKeyObj);

  const kmsSigningAlg = algorithmToKmsSigningAlg(algorithm);

  const metadata: SignerMetadata = {
    id,
    algorithm,
    type: "software",
    fingerprint,
    label: `aws-kms:${keyArn.split("/").pop() ?? keyArn}`,
  };

  return {
    id,
    algorithm,
    type: "software",
    metadata,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      // Hash the data before sending to KMS (KMS expects a digest for DIGEST message type)
      const digest = algorithm === "P-384"
        ? sha384(data)
        : sha256(data);

      const signRes = await client.send(
        new SignCommand({
          KeyId: keyArn,
          Message: digest,
          MessageType: "DIGEST",
          SigningAlgorithm: kmsSigningAlg,
        }),
      );

      return new Uint8Array(signRes.Signature!);
    },
  };
}
