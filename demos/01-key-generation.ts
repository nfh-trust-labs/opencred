import { LocalSigningKeyProvider } from "@opencred/crypto";
import { header, success, info, json, separator, step } from "./helpers.js";

export async function main(): Promise<void> {
  header("Demo 01: Key Generation & Management");

  // Step 1: Generate a fresh P-256 key pair
  step(1, "Generate a fresh ECDSA P-256 key pair");
  const provider = new LocalSigningKeyProvider();
  const activeKey = provider.getActiveKey();
  info(`Key ID (did:key): ${activeKey.id}`);
  info(`Algorithm: ${activeKey.algorithm}`);
  success("Key pair generated using CSPRNG");

  separator();

  // Step 2: Export public key as JWK
  step(2, "Export public key as JWK");
  const jwk = provider.getPublicKeyJwk(activeKey.id);
  json("Public Key JWK", jwk);
  success("Public key exported (private key stays in KeyObject — never serialized)");

  separator();

  // Step 3: List managed keys
  step(3, "List managed keys");
  const keys = provider.listKeys();
  json("Managed keys", keys);
  success(`${keys.length} key(s) in provider`);

  separator();

  // Step 4: Rotate key
  step(4, "Rotate to a new key");
  const newKey = provider.rotateKey();
  info(`New active key: ${newKey.id}`);
  const allKeys = provider.listKeys();
  info(`Total keys after rotation: ${allKeys.length}`);

  const oldKeyStillAvailable = provider.getKeyById(activeKey.id);
  if (oldKeyStillAvailable) {
    success("Old key remains available for verification of previously-signed credentials");
  }

  separator();

  // Step 5: Sign raw data
  step(5, "Sign arbitrary data with the active key");
  const data = new TextEncoder().encode("Hello, OpenCred!");
  const signature = provider.sign(data);
  info(`Signature length: ${signature.length} bytes (raw r||s for P-256)`);
  success("Data signed successfully");

  separator();
  success("Demo 01 complete");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
