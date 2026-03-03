import { LocalSigningKeyProvider, signCredential, verifyProof } from "@opencred/crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import type { VerifiableCredential } from "@opencred/vc-core";
import { header, success, info, json, separator, step, error } from "./helpers.js";

export async function main(): Promise<void> {
  header("Demo 05: Verification (Valid + Tampered)");

  // Step 1: Create and sign a credential
  step(1, "Create and sign a credential");
  const provider = new LocalSigningKeyProvider();
  const signingKey = provider.getActiveKey();

  const unsignedVC = new CredentialBuilder()
    .addType("UniversityDegreeCredential")
    .setIssuer("did:web:university.example")
    .setCredentialSubject({
      id: "did:example:holder123",
      name: "Jane Doe",
      degree: "Bachelor of Science",
      institution: "Example University",
    })
    .setValidFrom("2026-01-01T00:00:00Z")
    .setValidUntil("2030-12-31T23:59:59Z")
    .build();

  const signedVC = await signCredential(unsignedVC, signingKey, {
    verificationMethod: signingKey.id,
    proofPurpose: "assertionMethod",
  });
  success("Credential signed");

  separator();

  // Step 2: Verify the valid credential
  step(2, "Verify the untampered credential");
  const validResult = await verifyProof(signedVC, { publicKey: signingKey.publicKey });
  json("Verification result", validResult);
  if (validResult.verified) {
    success("Credential verified successfully");
  } else {
    error(`Unexpected failure: ${validResult.error}`);
  }

  separator();

  // Step 3: Tamper with the credential (modify the issuer field)
  step(3, "Tamper with credential (change issuer) and re-verify");
  info("Changing issuer from 'did:web:university.example' to 'did:web:attacker.example'");

  const tampered: VerifiableCredential = {
    ...signedVC,
    issuer: "did:web:attacker.example",
  };

  const tamperedResult = await verifyProof(tampered, { publicKey: signingKey.publicKey });
  json("Tampered verification result", tamperedResult);
  if (!tamperedResult.verified) {
    success("Tampered credential correctly rejected");
    info(`Reason: ${tamperedResult.error}`);
  } else {
    error("SECURITY ISSUE: tampered credential was accepted!");
  }

  separator();

  // Step 4: Verify with wrong key
  step(4, "Verify with a different (wrong) key");
  const wrongProvider = new LocalSigningKeyProvider();
  const wrongKey = wrongProvider.getActiveKey();
  const wrongKeyResult = await verifyProof(signedVC, { publicKey: wrongKey.publicKey });
  json("Wrong key verification result", wrongKeyResult);
  if (!wrongKeyResult.verified) {
    success("Verification with wrong key correctly rejected");
  } else {
    error("SECURITY ISSUE: wrong key accepted!");
  }

  separator();
  success("Demo 05 complete");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
