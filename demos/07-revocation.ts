import { jcsCanonicalize, computeRevocationHash } from "@opencred/crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import { header, success, info, json, separator, step } from "./helpers.js";

export async function main(): Promise<void> {
  header("Demo 07: Revocation Hashing (JCS)");

  // Step 1: Build a credential to hash
  step(1, "Build a credential for revocation hashing");
  const credential = new CredentialBuilder()
    .addType("UniversityDegreeCredential")
    .setId("urn:uuid:12345678-1234-1234-1234-123456789abc")
    .setIssuer("did:web:university.example")
    .setCredentialSubject({
      id: "did:example:holder123",
      name: "Jane Doe",
      degree: "Bachelor of Science",
      institution: "Example University",
    })
    .setValidFrom("2026-01-01T00:00:00Z")
    .build();

  json("Credential", credential);
  success("Credential built");

  separator();

  // Step 2: Canonicalize with JCS (RFC 8785)
  step(2, "Canonicalize credential with JCS (RFC 8785)");
  const canonical = jcsCanonicalize(credential);
  info(`Canonical form (first 120 chars): ${canonical.slice(0, 120)}...`);
  info(`Canonical length: ${canonical.length} chars`);
  success("JCS canonicalization complete — deterministic JSON output");

  separator();

  // Step 3: Compute revocation hash
  step(3, "Compute revocation hash (SHA-256 of JCS-canonical form)");
  const hash = computeRevocationHash(credential);
  info(`Revocation hash: ${hash}`);
  info("This hash is sent to the DeDi revocation registry");
  success("Revocation hash computed");

  separator();

  // Step 4: Demonstrate determinism
  step(4, "Demonstrate determinism — same input always produces same hash");
  const hash2 = computeRevocationHash(credential);
  if (hash === hash2) {
    success("Hash is deterministic: identical input produces identical hash");
  }

  // Reorder the object keys — JCS should produce the same output
  const reordered = {
    validFrom: credential.validFrom,
    credentialSubject: credential.credentialSubject,
    type: credential.type,
    "@context": credential["@context"],
    issuer: credential.issuer,
    id: credential.id,
  };
  const hash3 = computeRevocationHash(reordered);
  info(`Original key order hash:  ${hash}`);
  info(`Reordered key order hash: ${hash3}`);
  if (hash === hash3) {
    success("Key order does not affect the hash (JCS sorts keys deterministically)");
  }

  separator();

  // Step 5: Show that any change produces a different hash
  step(5, "Show that any modification changes the hash");
  const modified = { ...credential, validFrom: "2026-01-02T00:00:00Z" };
  const modifiedHash = computeRevocationHash(modified);
  info(`Original hash:  ${hash}`);
  info(`Modified hash:  ${modifiedHash}`);
  if (hash !== modifiedHash) {
    success("Different content produces a different hash");
  }

  separator();
  success("Demo 07 complete");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
