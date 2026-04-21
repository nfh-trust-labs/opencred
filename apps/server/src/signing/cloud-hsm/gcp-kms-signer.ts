/**
 * GCP Cloud KMS Signer — implements the Signer interface using GCP KMS asymmetricSign.
 *
 * Config from env: OPENCRED_GCP_KMS_KEY_NAME
 *   Format: projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
 *
 * SECURITY INVARIANTS:
 *  - The private key never leaves GCP Cloud KMS.
 *  - Key material is NEVER logged — only the key resource name and algorithm.
 *  - Uses Application Default Credentials for auth.
 */

import { createPublicKey } from "node:crypto";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import type { SigningAlgorithm } from "@opencred/crypto";
import { sha256, sha384 } from "@opencred/crypto";
import type { Signer, SignerMetadata } from "@opencred/signing";
import { computeFingerprint, deriveDidKeyIdFromPublicKey } from "@opencred/signing";

/**
 * Map GCP KMS algorithm to OpenCred SigningAlgorithm.
 */
function gcpAlgorithmToSigningAlgorithm(gcpAlg: string): SigningAlgorithm {
  if (gcpAlg.includes("EC_SIGN_P256")) return "P-256";
  if (gcpAlg.includes("EC_SIGN_P384")) return "P-384";
  if (gcpAlg.includes("RSA_SIGN") && gcpAlg.includes("2048")) return "RSA-2048";
  if (gcpAlg.includes("RSA_SIGN") && gcpAlg.includes("3072")) return "RSA-3072";
  if (gcpAlg.includes("RSA_SIGN") && gcpAlg.includes("4096")) return "RSA-4096";
  throw new Error(`Unsupported GCP KMS algorithm: ${gcpAlg}`);
}

/**
 * Map OpenCred algorithm to GCP digest type.
 */
function algorithmToGcpDigestField(alg: SigningAlgorithm): "sha256" | "sha384" {
  return alg === "P-384" ? "sha384" : "sha256";
}

/**
 * Create a Signer backed by GCP Cloud KMS.
 *
 * Anand's P1-03: the GCP KMS client's default grpc transport manages its
 * own channel pool and keepalive, so no extra agent plumbing is required.
 * The `@google-cloud/kms` client accepts a top-level `timeout` that is
 * applied across all gRPC retries plus exposes per-call timeouts via the
 * second argument to `asymmetricSign` / `getPublicKey` (see below). Tie the
 * constructor-level `timeout` to `timeoutMs` so that gRPC retries are
 * bounded at the SDK level, not just per call.
 */
export async function createGcpKmsSigner(keyName: string, timeoutMs = 30_000): Promise<Signer> {
  const client = new KeyManagementServiceClient({ timeout: timeoutMs });

  // Get the public key to determine algorithm and derive DID
  const [publicKeyResponse] = await client.getPublicKey({ name: keyName }, { timeout: timeoutMs });
  const gcpAlgorithm = publicKeyResponse.algorithm!;
  const algorithm = gcpAlgorithmToSigningAlgorithm(gcpAlgorithm as string);

  // Convert PEM to KeyObject for fingerprint/DID derivation
  const pemStr = publicKeyResponse.pem!;
  const publicKeyObj = createPublicKey({ key: pemStr, format: "pem" });

  const fingerprint = computeFingerprint(publicKeyObj);
  const id = deriveDidKeyIdFromPublicKey(publicKeyObj);

  const digestField = algorithmToGcpDigestField(algorithm);

  // Extract short name from full resource path
  const shortName = keyName.split("/").pop() ?? keyName;

  const metadata: SignerMetadata = {
    id,
    algorithm,
    type: "software",
    fingerprint,
    label: `gcp-kms:${shortName}`,
  };

  return {
    id,
    algorithm,
    type: "software",
    metadata,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      const digest = digestField === "sha384" ? sha384(data) : sha256(data);

      const [signResponse] = await client.asymmetricSign(
        {
          name: keyName,
          digest: { [digestField]: digest },
        },
        { timeout: timeoutMs },
      );

      return new Uint8Array(signResponse.signature as Uint8Array);
    },
  };
}
