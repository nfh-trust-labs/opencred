# Cloud HSM Integration

Cloud HSM support is available in the Docker/server deployment only. Private keys never leave the HSM -- signing requests are sent to the cloud provider's API, which returns the signature.

## Overview

Set `OPENCRED_KMS_PROVIDER` to your provider and supply the provider-specific variables. The server loads the signing key at startup and uses it for all credential operations.

When `OPENCRED_KMS_PROVIDER` is `none` (the default), the server falls back to file-based key loading via `OPENCRED_KEY_PATH`.

## AWS KMS

```bash
OPENCRED_KMS_PROVIDER=aws
OPENCRED_KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/abcd-1234-efgh-5678
```

**Key Requirements:**
- Asymmetric signing key (not encryption)
- Key spec: `ECC_NIST_P256` or `ECC_NIST_P384`
- Key usage: `SIGN_VERIFY`

**Authentication:** AWS SDK default credential chain -- environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), instance profile, ECS task role, etc.

**Required IAM Permissions:**
- `kms:Sign`
- `kms:GetPublicKey`
- `kms:DescribeKey`

## Azure Key Vault

```bash
OPENCRED_KMS_PROVIDER=azure
OPENCRED_AZURE_KEY_VAULT_URL=https://your-vault.vault.azure.net
OPENCRED_AZURE_KEY_NAME=issuer-signing-key
```

**Key Requirements:**
- EC key in Azure Key Vault
- Supported curves: P-256, P-384

**Authentication:** Azure `DefaultAzureCredential` -- environment variables, managed identity, Azure CLI, etc.

**Required Permissions:**
- Key Sign
- Key Get (to retrieve public key)

## GCP Cloud KMS

```bash
OPENCRED_KMS_PROVIDER=gcp
OPENCRED_GCP_KMS_KEY_NAME=projects/my-project/locations/us-east1/keyRings/my-ring/cryptoKeys/issuer-key/cryptoKeyVersions/1
```

**Key Requirements:**
- Asymmetric signing key
- Algorithm: `EC_SIGN_P256_SHA256` or `EC_SIGN_P384_SHA384`

**Authentication:** Google Cloud Application Default Credentials -- environment variable (`GOOGLE_APPLICATION_CREDENTIALS`), compute metadata, gcloud CLI, etc.

**Required Permissions:**
- `cloudkms.cryptoKeyVersions.useToSign`
- `cloudkms.cryptoKeyVersions.viewPublicKey`

## Verifying HSM Setup

After starting the server, check the health endpoint:

```bash
curl http://localhost:3100/health
```

If `signingKeyLoaded` is `true`, the HSM key was loaded successfully. The startup logs also show the provider, key ID, fingerprint, and algorithm.
