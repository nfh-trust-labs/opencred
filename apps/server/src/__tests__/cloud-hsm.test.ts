/**
 * Cloud HSM mock tests — verifies signer factory and adapter behavior.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { loadConfig, resetConfig } from "../config.js";
import { createLogger, resetLogger } from "../logger.js";

// Generate a test P-256 key pair for mocking
const testKeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const testPublicKeyDer = testKeyPair.publicKey.export({ type: "spki", format: "der" });
const testPublicKeyPem = testKeyPair.publicKey.export({ type: "spki", format: "pem" }) as string;
const fakeSignature = new Uint8Array(64).fill(0xab);

// ---------------------------------------------------------------------------
// AWS KMS mocks
// ---------------------------------------------------------------------------

vi.mock("@aws-sdk/client-kms", () => {
  return {
    KMSClient: vi.fn().mockImplementation(() => ({
      send: vi.fn().mockImplementation((command: { constructor: { name: string } }) => {
        if (command.constructor.name === "DescribeKeyCommand") {
          return { KeyMetadata: { KeySpec: "ECC_NIST_P256" } };
        }
        if (command.constructor.name === "GetPublicKeyCommand") {
          return { PublicKey: testPublicKeyDer };
        }
        if (command.constructor.name === "SignCommand") {
          return { Signature: fakeSignature };
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    })),
    DescribeKeyCommand: vi.fn().mockImplementation(function (this: { constructor: { name: string } }) {
      Object.defineProperty(this.constructor, "name", { value: "DescribeKeyCommand" });
    }),
    GetPublicKeyCommand: vi.fn().mockImplementation(function (this: { constructor: { name: string } }) {
      Object.defineProperty(this.constructor, "name", { value: "GetPublicKeyCommand" });
    }),
    SignCommand: vi.fn().mockImplementation(function (this: { constructor: { name: string } }) {
      Object.defineProperty(this.constructor, "name", { value: "SignCommand" });
    }),
  };
});

// ---------------------------------------------------------------------------
// Azure Key Vault mocks
// ---------------------------------------------------------------------------

vi.mock("@azure/identity", () => ({
  DefaultAzureCredential: vi.fn(),
}));

vi.mock("@azure/keyvault-keys", () => {
  const ecJwk = testKeyPair.publicKey.export({ format: "jwk" });
  return {
    KeyClient: vi.fn().mockImplementation(() => ({
      getKey: vi.fn().mockResolvedValue({
        id: "https://vault.azure.net/keys/test-key/abc123",
        key: {
          kty: "EC",
          crv: "P-256",
          x: ecJwk.x ? Buffer.from(ecJwk.x, "base64url") : undefined,
          y: ecJwk.y ? Buffer.from(ecJwk.y, "base64url") : undefined,
        },
      }),
    })),
    CryptographyClient: vi.fn().mockImplementation(() => ({
      sign: vi.fn().mockResolvedValue({ result: fakeSignature }),
    })),
  };
});

// ---------------------------------------------------------------------------
// GCP KMS mocks
// ---------------------------------------------------------------------------

vi.mock("@google-cloud/kms", () => ({
  KeyManagementServiceClient: vi.fn().mockImplementation(() => ({
    getPublicKey: vi.fn().mockResolvedValue([
      {
        algorithm: "EC_SIGN_P256_SHA256",
        pem: testPublicKeyPem,
      },
    ]),
    asymmetricSign: vi.fn().mockResolvedValue([
      {
        signature: fakeSignature,
      },
    ]),
  })),
}));

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

function setupEnv(kmsProvider: string) {
  resetConfig();
  resetLogger();
  delete process.env.OPENCRED_API_KEY;
  process.env.OPENCRED_PORT = "3199";
  process.env.OPENCRED_LOG_LEVEL = "fatal";
  process.env.OPENCRED_KMS_PROVIDER = kmsProvider;

  if (kmsProvider === "aws") {
    process.env.OPENCRED_KMS_KEY_ARN = "arn:aws:kms:us-east-1:123456789:key/test-key-id";
  }
  if (kmsProvider === "azure") {
    process.env.OPENCRED_AZURE_KEY_VAULT_URL = "https://test-vault.vault.azure.net";
    process.env.OPENCRED_AZURE_KEY_NAME = "test-key";
  }
  if (kmsProvider === "gcp") {
    process.env.OPENCRED_GCP_KMS_KEY_NAME =
      "projects/test/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";
  }

  loadConfig();
  createLogger();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Cloud HSM factory", () => {
  beforeEach(() => {
    // Clear KMS env vars
    delete process.env.OPENCRED_KMS_PROVIDER;
    delete process.env.OPENCRED_KMS_KEY_ARN;
    delete process.env.OPENCRED_AZURE_KEY_VAULT_URL;
    delete process.env.OPENCRED_AZURE_KEY_NAME;
    delete process.env.OPENCRED_GCP_KMS_KEY_NAME;
    delete process.env.OPENCRED_KEY_PATH;
  });

  it("returns null (file-based fallback) when no provider set", async () => {
    setupEnv("none");
    // Dynamically import to get fresh module with mocked deps
    const { createSignerFromConfig } = await import("../signing/cloud-hsm/factory.js");
    const signer = await createSignerFromConfig();
    // No key path set, so file-based returns null
    expect(signer).toBeNull();
  });
});

describe("AWS KMS signer", () => {
  it("creates a signer with correct algorithm", async () => {
    setupEnv("aws");
    const { createAwsKmsSigner } = await import("../signing/cloud-hsm/aws-kms-signer.js");
    const signer = await createAwsKmsSigner("arn:aws:kms:us-east-1:123456789:key/test-key-id");

    expect(signer.algorithm).toBe("P-256");
    expect(signer.id).toBeTruthy();
    expect(signer.metadata.fingerprint).toBeTruthy();
  });

  it("sign() returns correct bytes from mocked KMS", async () => {
    setupEnv("aws");
    const { createAwsKmsSigner } = await import("../signing/cloud-hsm/aws-kms-signer.js");
    const signer = await createAwsKmsSigner("arn:aws:kms:us-east-1:123456789:key/test-key-id");

    const data = new TextEncoder().encode("test data");
    const signature = await signer.sign(data);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });
});

describe("Azure Key Vault signer", () => {
  it("creates a signer with correct algorithm", async () => {
    setupEnv("azure");
    const { createAzureKvSigner } = await import("../signing/cloud-hsm/azure-kv-signer.js");
    const signer = await createAzureKvSigner(
      "https://test-vault.vault.azure.net",
      "test-key",
    );

    expect(signer.algorithm).toBe("P-256");
    expect(signer.id).toBeTruthy();
    expect(signer.metadata.fingerprint).toBeTruthy();
    expect(signer.metadata.label).toBe("azure-kv:test-key");
  });

  it("sign() returns correct bytes from mocked Azure", async () => {
    setupEnv("azure");
    const { createAzureKvSigner } = await import("../signing/cloud-hsm/azure-kv-signer.js");
    const signer = await createAzureKvSigner(
      "https://test-vault.vault.azure.net",
      "test-key",
    );

    const data = new TextEncoder().encode("test data");
    const signature = await signer.sign(data);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });
});

describe("GCP Cloud KMS signer", () => {
  it("creates a signer with correct algorithm", async () => {
    setupEnv("gcp");
    const { createGcpKmsSigner } = await import("../signing/cloud-hsm/gcp-kms-signer.js");
    const signer = await createGcpKmsSigner(
      "projects/test/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1",
    );

    expect(signer.algorithm).toBe("P-256");
    expect(signer.id).toBeTruthy();
    expect(signer.metadata.fingerprint).toBeTruthy();
    expect(signer.metadata.label).toContain("gcp-kms:");
  });

  it("sign() returns correct bytes from mocked GCP", async () => {
    setupEnv("gcp");
    const { createGcpKmsSigner } = await import("../signing/cloud-hsm/gcp-kms-signer.js");
    const signer = await createGcpKmsSigner(
      "projects/test/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1",
    );

    const data = new TextEncoder().encode("test data");
    const signature = await signer.sign(data);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });
});
