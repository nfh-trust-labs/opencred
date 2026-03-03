import { LocalSigningKeyProvider, signCredential } from "@opencred/crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import { header, success, info, json, separator, step } from "./helpers.js";

export async function main(): Promise<void> {
  header("Demo 02: Credential Issuance (Delegated Signing)");

  // Step 1: Set up signing key
  step(1, "Create a signing key provider");
  const provider = new LocalSigningKeyProvider();
  const signingKey = provider.getActiveKey();
  info(`Signing key: ${signingKey.id}`);
  success("Signing key ready");

  separator();

  // Step 2: Build an unsigned credential using CredentialBuilder
  step(2, "Build an unsigned credential");
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

  json("Unsigned VC", unsignedVC);
  success("Unsigned credential built with CredentialBuilder");

  separator();

  // Step 3: Sign the credential with a Data Integrity proof
  step(3, "Sign credential (ecdsa-rdfc-2019 Data Integrity proof)");
  const signedVC = await signCredential(unsignedVC, signingKey, {
    verificationMethod: signingKey.id,
    proofPurpose: "assertionMethod",
  });

  json("Signed VC (proof section)", {
    type: signedVC.proof.type,
    cryptosuite: signedVC.proof.cryptosuite,
    created: signedVC.proof.created,
    verificationMethod: signedVC.proof.verificationMethod,
    proofPurpose: signedVC.proof.proofPurpose,
    proofValue: signedVC.proof.proofValue.slice(0, 40) + "...",
  });
  success("Credential signed with ecdsa-rdfc-2019 Data Integrity proof");

  separator();
  success("Demo 02 complete");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
