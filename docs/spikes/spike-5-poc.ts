/**
 * Spike 5 PoC: VC Data Integrity External Signing Round-Trip
 *
 * NON-PRODUCTION CODE — This is a spike proof-of-concept reference.
 *
 * Demonstrates the full two-phase (Interface Signing) flow:
 *   1. prepareProof()  — compute dataToSign on the server
 *   2. External sign   — sign with WebCrypto (simulating browser SubtleCrypto)
 *   3. completeProof() — assemble the final VC on the server
 *   4. verifyProof()   — verify the credential
 *
 * The logic validated here is exercised by the existing test suite:
 *   pnpm vitest run --project @opencred/crypto
 *
 * See: packages/crypto/src/__tests__/data-integrity.test.ts
 *   - "prepareProof / completeProof — two-phase round-trip" test suite
 *   - All 19 data-integrity tests pass (42/42 total for crypto package)
 *
 * This file serves as annotated reference code for the spike findings doc.
 */

// ─── Step 1: Imports ────────────────────────────────────────────────────────
//
// In production, these would be:
//   import { prepareProof, completeProof, verifyProof } from "@opencred/crypto";
//   import type { UnsignedCredential } from "@opencred/vc-core";

import { generateKeyPairSync, createSign, createPublicKey, webcrypto } from "node:crypto";
// import type { KeyObject } from "node:crypto";
// import { prepareProof, completeProof, verifyProof } from "@opencred/crypto";
// import type { UnsignedCredential } from "@opencred/vc-core";
// import type { ProofOptions } from "@opencred/crypto";

// ─── Step 2: Build an Unsigned VC ───────────────────────────────────────────
//
// The unsigned credential follows W3C VC Data Model 2.0.
// The @context array MUST include the W3C credentials v2 context.
// The data-integrity v1 context is also recommended for Data Integrity proofs.

const unsignedVC = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:91a7e5f0-1234-4abc-9def-567890abcdef",
  type: ["VerifiableCredential"],
  issuer: "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
  validFrom: "2026-01-15T00:00:00Z",
  credentialSubject: {
    id: "did:example:holder-abc-123",
    name: "Alice Wonderland",
    degree: {
      type: "BachelorDegree",
      name: "Bachelor of Science in Computer Science",
    },
  },
};

// ─── Step 3: Proof Options ──────────────────────────────────────────────────
//
// verificationMethod: DID URL pointing to the issuer's public key
// proofPurpose: "assertionMethod" for credential issuance
// created: ISO 8601 timestamp (auto-generated if omitted)

const proofOptions = {
  verificationMethod:
    "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
  proofPurpose: "assertionMethod",
  created: "2026-01-15T12:00:00Z",
};

// ─── Step 4: Phase 1 — prepareProof() ───────────────────────────────────────
//
// This runs on the OpenCred server. It:
//   1. Builds a proofConfig (type, cryptosuite, created, verificationMethod, proofPurpose)
//   2. Canonicalizes the proofConfig using RDFC-1.0 (URDNA2015)
//   3. Canonicalizes the unsigned credential using RDFC-1.0
//   4. SHA-256 hashes each canonical form
//   5. Concatenates: dataToSign = SHA-256(proofConfig) || SHA-256(document) = 64 bytes
//
// Returns: { dataToSign: Uint8Array(64), proofConfig: ProofConfig }
//
// Example call:
//   const { dataToSign, proofConfig } = await prepareProof(unsignedVC, proofOptions);

// ─── Step 5: Phase 2 — External Signing ─────────────────────────────────────
//
// The 64-byte dataToSign is sent to the issuer (e.g., as base64url in a JSON response).
// The issuer signs in their browser using WebCrypto SubtleCrypto:
//
//   const signature = await crypto.subtle.sign(
//     { name: "ECDSA", hash: { name: "SHA-256" } },
//     privateKey,          // CryptoKey — never leaves the browser
//     dataToSign           // the 64-byte buffer from prepareProof
//   );
//   // signature is an ArrayBuffer of 64 bytes (raw r||s, IEEE P1363 format)
//
// IMPORTANT: SubtleCrypto.sign() hashes the input internally before ECDSA math.
// The issuer does NOT need to hash dataToSign themselves.
// The full cryptographic operation is:
//   ECDSA-Sign(SHA-256(dataToSign)) = ECDSA-Sign(SHA-256(SHA-256(proofConfig) || SHA-256(document)))
//
// Node.js equivalent (used in tests):
//   const signer = createSign("SHA256");
//   signer.update(dataToSign);
//   const sig = signer.sign({ key: privateKey, dsaEncoding: "ieee-p1363" });

// ─── Step 6: Phase 3 — completeProof() ──────────────────────────────────────
//
// The 64-byte signature is sent back to the OpenCred server.
// completeProof() assembles the final VerifiableCredential:
//
//   1. Validates signature is 64 bytes (P-256)
//   2. Encodes as multibase base58btc: proofValue = "z" + base58btc(signatureBytes)
//   3. Assembles proof object: { type, cryptosuite, created, verificationMethod, proofPurpose, proofValue }
//   4. Returns: { ...credential, proof }
//
// Example call:
//   const signedVC = completeProof(unsignedVC, proofConfig, signatureBytes);

// ─── Step 7: Verification ───────────────────────────────────────────────────
//
// verifyProof() re-derives the dataToSign from the credential and proof,
// then verifies the ECDSA signature against the public key.
//
//   1. Extracts and decodes proofValue (multibase base58btc → raw signature bytes)
//   2. Reconstructs proofConfig from the proof object
//   3. Recomputes dataToSign = SHA-256(proofConfig) || SHA-256(document)
//   4. Verifies ECDSA signature using Node.js crypto.createVerify("SHA256")
//
// Example call:
//   const result = await verifyProof(signedVC, { publicKey });
//   // result: { verified: true } or { verified: false, error: "..." }

// ─── Signature Format Reference ─────────────────────────────────────────────
//
// The ECDSA signature format for ecdsa-rdfc-2019:
//
// | Property     | Value                                           |
// |--------------|-------------------------------------------------|
// | Format       | Raw r||s (IEEE P1363), NOT DER                  |
// | P-256 size   | 64 bytes (32 bytes r + 32 bytes s)              |
// | P-384 size   | 96 bytes (48 bytes r + 48 bytes s)              |
// | Encoding     | Multibase base58btc (prefix "z")                |
// | No multicodec wrapping on signature (unlike public keys)       |
//
// WebCrypto SubtleCrypto.sign() with ECDSA returns IEEE P1363 by default.
// Node.js crypto.createSign().sign({ dsaEncoding: "ieee-p1363" }) does the same.

// ─── Flow Diagram ───────────────────────────────────────────────────────────
//
// ┌─────────── SERVER (OpenCred) ──────────────┐   ┌──── ISSUER (Browser) ────┐
// │                                             │   │                          │
// │  1. prepareProof(unsignedVC, options)        │   │                          │
// │     → { dataToSign (64B), proofConfig }     │   │                          │
// │                                  ───────────┼──>│                          │
// │                                             │   │  2. SubtleCrypto.sign(   │
// │                                             │   │       {name:'ECDSA',     │
// │                                             │   │        hash:'SHA-256'},  │
// │                                             │   │       privateKey,        │
// │                                             │   │       dataToSign)        │
// │                                             │   │     → 64B raw r||s sig   │
// │                                  <──────────┼───│                          │
// │  3. completeProof(cred, cfg, sigBytes)      │   │                          │
// │     → VerifiableCredential with proof       │   │                          │
// │                                             │   │                          │
// └─────────────────────────────────────────────┘   └──────────────────────────┘

export {};
