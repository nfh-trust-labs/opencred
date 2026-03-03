import { LocalSigningKeyProvider, signCredential } from "@opencred/crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import {
  createDelegationCertificate,
  isDelegationAuthorised,
  validateDelegationCertificate,
  embedDelegation,
} from "@opencred/delegation";
import type { DelegationCertificate } from "@opencred/delegation";
import { header, success, info, warn, json, separator, step, error } from "./helpers.js";

export async function main(): Promise<void> {
  header("Demo 04: Delegation Lifecycle");

  // Step 1: Set up issuer (delegator) and OpenCred (delegatee) keys
  step(1, "Create delegator (issuer) and delegatee (OpenCred) keys");
  const issuerProvider = new LocalSigningKeyProvider();
  const issuerKey = issuerProvider.getActiveKey();
  const opencredProvider = new LocalSigningKeyProvider();
  const opencredKey = opencredProvider.getActiveKey();
  info(`Delegator (issuer): ${issuerKey.id.slice(0, 50)}...`);
  info(`Delegatee (OpenCred): ${opencredKey.id.slice(0, 50)}...`);
  success("Both key pairs generated");

  separator();

  // Step 2: Create an unsigned delegation certificate
  step(2, "Create unsigned delegation certificate");
  const unsignedCert = createDelegationCertificate({
    delegator: {
      id: "did:web:university.example",
      name: "Example University",
    },
    delegatee: {
      id: opencredKey.id,
    },
    scope: {
      credentialTypes: ["UniversityDegreeCredential"],
      namespaces: ["education"],
      maxIssuanceCount: 1000,
    },
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    authorisationPath: "ephemeral-keypair",
  });

  json("Unsigned delegation cert", {
    id: unsignedCert.id,
    type: unsignedCert.type,
    delegator: unsignedCert.delegator,
    delegatee: { id: unsignedCert.delegatee.id.slice(0, 50) + "..." },
    scope: unsignedCert.scope,
    validFrom: unsignedCert.validFrom,
    validUntil: unsignedCert.validUntil,
  });
  success("Unsigned delegation certificate created");

  separator();

  // Step 3: Issuer signs the delegation certificate
  step(3, "Issuer signs the delegation certificate");
  const signedCert = (await signCredential(
    unsignedCert as unknown as ReturnType<CredentialBuilder["build"]>,
    issuerKey,
    {
      verificationMethod: issuerKey.id,
      proofPurpose: "assertionMethod",
    },
  )) as unknown as DelegationCertificate;
  info(`Proof type: ${signedCert.proof!.type}`);
  success("Delegation certificate signed by the issuer");

  separator();

  // Step 4: Validate the delegation certificate
  step(4, "Validate the signed delegation certificate");
  const validationResult = await validateDelegationCertificate(signedCert, {
    delegatorPublicKey: issuerKey.publicKey,
    credentialType: "UniversityDegreeCredential",
    namespace: "education",
  });
  json("Validation result", validationResult);
  if (validationResult.valid) {
    success(`Status: ${validationResult.status}`);
  } else {
    error(`Validation failed: ${validationResult.errors.join(", ")}`);
  }

  separator();

  // Step 5: Check authorisation for specific types
  step(5, "Check isDelegationAuthorised for different scenarios");

  const authorisedEdu = isDelegationAuthorised(
    signedCert,
    "UniversityDegreeCredential",
    "education",
  );
  if (authorisedEdu) {
    success("UniversityDegreeCredential in 'education' namespace: AUTHORISED");
  }

  const authorisedHealth = isDelegationAuthorised(
    signedCert,
    "HealthCertificate",
    "health",
  );
  if (!authorisedHealth) {
    warn("HealthCertificate in 'health' namespace: NOT AUTHORISED (out of scope)");
  }

  separator();

  // Step 6: Use the delegation to sign a credential
  step(6, "OpenCred signs a credential under the delegation");
  const unsignedVC = new CredentialBuilder()
    .addType("UniversityDegreeCredential")
    .setIssuer("did:web:university.example")
    .setCredentialSubject({
      id: "did:example:student789",
      name: "Alice Johnson",
      degree: "Master of Arts",
      institution: "Example University",
    })
    .setValidFrom("2026-06-01T00:00:00Z")
    .setValidUntil("2030-06-01T00:00:00Z")
    .build();

  const signedVC = await signCredential(unsignedVC, opencredKey, {
    verificationMethod: opencredKey.id,
    proofPurpose: "assertionMethod",
  });
  success("Credential signed by OpenCred's delegated key");

  // Embed the delegation certificate in the credential
  const vcWithDelegation = embedDelegation(signedVC, signedCert);
  info("Delegation certificate embedded inline in the credential proof");
  success("Verifier can now trace: VC proof -> OpenCred key -> delegation cert -> issuer");

  separator();
  success("Demo 04 complete");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
