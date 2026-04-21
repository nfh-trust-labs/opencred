/**
 * Cloud HSM signer factory — reads OPENCRED_KMS_PROVIDER env var and returns
 * the appropriate Signer implementation.
 *
 * Supported providers: aws, azure, gcp, none (default).
 * When provider is "none" or unset, falls back to file-based key manager.
 *
 * SECURITY INVARIANTS:
 *  - Key material is NEVER logged — only provider name and key identifier.
 *  - Each cloud provider's SDK handles authentication via its own credential chain.
 */

import type { Signer } from "@opencred/signing";
import { getConfig } from "../../config.js";
import { getLogger } from "../../logger.js";
import { loadSigningKey } from "../key-manager.js";
import { createAwsKmsSigner } from "./aws-kms-signer.js";
import { createAzureKvSigner } from "./azure-kv-signer.js";
import { createGcpKmsSigner } from "./gcp-kms-signer.js";

export type KmsProvider = "aws" | "azure" | "gcp" | "none";

/**
 * Create a Signer based on the configured KMS provider.
 * Falls back to the file-based key manager when no KMS provider is set.
 */
export async function createSignerFromConfig(): Promise<Signer | null> {
  const config = getConfig();
  const logger = getLogger();
  const provider = (config.OPENCRED_KMS_PROVIDER ?? "none") as KmsProvider;

  switch (provider) {
    case "aws": {
      const keyArn = config.OPENCRED_KMS_KEY_ARN;
      if (!keyArn) {
        throw new Error("OPENCRED_KMS_PROVIDER=aws requires OPENCRED_KMS_KEY_ARN");
      }
      logger.info({ provider: "aws" }, "Initializing AWS KMS signer");
      const signer = await createAwsKmsSigner(keyArn, config.OPENCRED_KMS_TIMEOUT_MS);
      logger.info(
        { keyId: signer.id, fingerprint: signer.metadata.fingerprint, algorithm: signer.algorithm },
        "AWS KMS signer ready",
      );
      return signer;
    }

    case "azure": {
      const vaultUrl = config.OPENCRED_AZURE_KEY_VAULT_URL;
      const keyName = config.OPENCRED_AZURE_KEY_NAME;
      if (!vaultUrl || !keyName) {
        throw new Error(
          "OPENCRED_KMS_PROVIDER=azure requires OPENCRED_AZURE_KEY_VAULT_URL and OPENCRED_AZURE_KEY_NAME",
        );
      }
      logger.info({ provider: "azure" }, "Initializing Azure Key Vault signer");
      const signer = await createAzureKvSigner(vaultUrl, keyName, config.OPENCRED_KMS_TIMEOUT_MS);
      logger.info(
        { keyId: signer.id, fingerprint: signer.metadata.fingerprint, algorithm: signer.algorithm },
        "Azure Key Vault signer ready",
      );
      return signer;
    }

    case "gcp": {
      const gcpKeyName = config.OPENCRED_GCP_KMS_KEY_NAME;
      if (!gcpKeyName) {
        throw new Error("OPENCRED_KMS_PROVIDER=gcp requires OPENCRED_GCP_KMS_KEY_NAME");
      }
      logger.info({ provider: "gcp" }, "Initializing GCP Cloud KMS signer");
      const signer = await createGcpKmsSigner(gcpKeyName, config.OPENCRED_KMS_TIMEOUT_MS);
      logger.info(
        { keyId: signer.id, fingerprint: signer.metadata.fingerprint, algorithm: signer.algorithm },
        "GCP Cloud KMS signer ready",
      );
      return signer;
    }

    case "none":
    default: {
      logger.info("No KMS provider configured — falling back to file-based key manager");
      return loadSigningKey();
    }
  }
}
