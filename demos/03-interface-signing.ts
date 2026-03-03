import { createSign } from "node:crypto";
import {
  LocalSigningKeyProvider,
  prepareProof,
  completeProof,
  verifyProof,
} from "@opencred/crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import { header, success, info, json, separator, step } from "./helpers.js";

export async function main(): Promise<void> {
  header("Demo 03: Interface Signing (Two-Phase Flow)");

  info("Interface Signing sends a signing payload TO the issuer.");
  info("The issuer's private key never leaves their control.\n");

  // Step 1: Set up the issuer's key (simulating an external issuer)
  step(1, "Simulate issuer key (in real use, this stays in issuer's browser/HSM)");
  const issuerProvider = new LocalSigningKeyProvider();
  const issuerKey = issuerProvider.getActiveKey();
  info(`Issuer verification method: ${issuerKey.id}`);
  success("Issuer key created (simulating browser-side key)");

  separator();

  // Step 2: Build the unsigned credential
  step(2, "Build unsigned credential on the server side");
  const unsignedVC = new CredentialBuilder()
    .addType("EmploymentCredential")
    .setIssuer("did:web:employer.example")
    .setCredentialSubject({
      id: "did:example:employee456",
      name: "John Smith",
      position: "Software Engineer",
      employer: "Example Corp",
    })
    .setValidFrom("2026-03-01T00:00:00Z")
    .setValidUntil("2027-03-01T00:00:00Z")
    .build();
  success("Unsigned credential built on server");

  separator();

  // Step 3: Phase 1 — Prepare the proof (server side)
  step(3, "Phase 1 — prepareProof() computes data to sign");
  const prepared = await prepareProof(unsignedVC, {
    verificationMethod: issuerKey.id,
    proofPurpose: "assertionMethod",
  });

  info(`Data to sign: ${prepared.dataToSign.length} bytes (SHA-256(proofConfig) || SHA-256(doc))`);
  json("Proof config", {
    type: prepared.proofConfig.type,
    cryptosuite: prepared.proofConfig.cryptosuite,
    verificationMethod: prepared.proofConfig.verificationMethod,
  });
  success("Signing payload prepared — this gets sent to the issuer's browser");

  separator();

  // Step 4: External signing (simulating the issuer's browser)
  step(4, "Issuer signs the payload (simulating SubtleCrypto in browser)");
  const signer = createSign("SHA256");
  signer.update(prepared.dataToSign);
  const signatureBytes = new Uint8Array(
    signer.sign({ key: issuerKey.privateKey, dsaEncoding: "ieee-p1363" }),
  );
  info(`Signature: ${signatureBytes.length} bytes (raw r||s)`);
  success("Issuer signed the payload — signature sent back to server");

  separator();

  // Step 5: Phase 2 — Complete the proof (server side)
  step(5, "Phase 2 — completeProof() assembles the final credential");
  const signedVC = completeProof(unsignedVC, prepared.proofConfig, signatureBytes);
  json("Signed VC proof", {
    type: signedVC.proof.type,
    cryptosuite: signedVC.proof.cryptosuite,
    proofValue: signedVC.proof.proofValue.slice(0, 40) + "...",
  });
  success("Verifiable Credential assembled with issuer's signature");

  separator();

  // Step 6: Verify the credential
  step(6, "Verify the credential using issuer's public key");
  const result = await verifyProof(signedVC, { publicKey: issuerKey.publicKey });
  if (result.verified) {
    success("Proof verified — issuer's key never left their control");
  } else {
    throw new Error(`Verification failed: ${result.error}`);
  }

  separator();
  success("Demo 03 complete");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
