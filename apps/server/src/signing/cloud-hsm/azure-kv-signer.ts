/**
 * Azure Key Vault Signer — implements the Signer interface using Azure Key Vault CryptographyClient.
 *
 * Config from env: OPENCRED_AZURE_KEY_VAULT_URL, OPENCRED_AZURE_KEY_NAME
 *
 * SECURITY INVARIANTS:
 *  - The private key never leaves Azure Key Vault.
 *  - Key material is NEVER logged — only the key name and algorithm.
 *  - Uses DefaultAzureCredential for auth (managed identity, env creds, CLI).
 */

import { createPublicKey } from "node:crypto";
import { DefaultAzureCredential } from "@azure/identity";
import { CryptographyClient, KeyClient } from "@azure/keyvault-keys";
import type { SigningAlgorithm } from "@opencred/crypto";
import { sha256, sha384 } from "@opencred/crypto";
import type { Signer, SignerMetadata } from "@opencred/signing";
import { computeFingerprint, deriveDidKeyIdFromPublicKey } from "@opencred/signing";

/**
 * Map Azure key curve/type to OpenCred SigningAlgorithm.
 */
function azureKeyToAlgorithm(kty: string, crv?: string, keySize?: number): SigningAlgorithm {
  if (kty === "EC" || kty === "EC-HSM") {
    switch (crv) {
      case "P-256":
        return "P-256";
      case "P-384":
        return "P-384";
      default:
        throw new Error(`Unsupported Azure EC curve: ${crv}`);
    }
  }
  if (kty === "RSA" || kty === "RSA-HSM") {
    if (keySize && keySize <= 2048) return "RSA-2048";
    if (keySize && keySize <= 3072) return "RSA-3072";
    return "RSA-4096";
  }
  throw new Error(`Unsupported Azure key type: ${kty}`);
}

/**
 * Map OpenCred algorithm to Azure signing algorithm name.
 */
function algorithmToAzureSignAlg(alg: SigningAlgorithm): string {
  switch (alg) {
    case "P-256":
      return "ES256";
    case "P-384":
      return "ES384";
    case "RSA-2048":
    case "RSA-3072":
    case "RSA-4096":
      return "PS256";
    default:
      throw new Error(`Unsupported algorithm for Azure Key Vault: ${alg}`);
  }
}

/**
 * Create a Signer backed by Azure Key Vault.
 */
export async function createAzureKvSigner(vaultUrl: string, keyName: string): Promise<Signer> {
  const credential = new DefaultAzureCredential();
  const keyClient = new KeyClient(vaultUrl, credential);

  // Get key to determine algorithm and derive DID
  const key = await keyClient.getKey(keyName);
  const jwk = key.key!;

  const algorithm = azureKeyToAlgorithm(jwk.kty!, jwk.crv, jwk.n ? jwk.n.length * 6 : undefined);

  // Build a JWK for Node.js createPublicKey
  const nodeJwk: Record<string, unknown> = { kty: jwk.kty };
  if (jwk.crv) nodeJwk.crv = jwk.crv;
  if (jwk.x) nodeJwk.x = Buffer.from(jwk.x).toString("base64url");
  if (jwk.y) nodeJwk.y = Buffer.from(jwk.y).toString("base64url");
  if (jwk.n) nodeJwk.n = Buffer.from(jwk.n).toString("base64url");
  if (jwk.e) nodeJwk.e = Buffer.from(jwk.e).toString("base64url");

  const publicKeyObj = createPublicKey({ key: nodeJwk, format: "jwk" });

  const fingerprint = computeFingerprint(publicKeyObj);
  const id = deriveDidKeyIdFromPublicKey(publicKeyObj);

  const cryptoClient = new CryptographyClient(key.id!, credential);
  const azureAlg = algorithmToAzureSignAlg(algorithm);

  const metadata: SignerMetadata = {
    id,
    algorithm,
    type: "software",
    fingerprint,
    label: `azure-kv:${keyName}`,
  };

  return {
    id,
    algorithm,
    type: "software",
    metadata,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      // Azure sign expects a digest
      const digest = algorithm === "P-384" ? sha384(data) : sha256(data);

      const result = await cryptoClient.sign(azureAlg, digest);
      return new Uint8Array(result.result);
    },
  };
}
