import { generateKeyPairSync, createVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildSigner,
  createSoftwareSigner,
} from "@opencred/signing/software-signer";
import type { Signer } from "@opencred/signing/types";
import {
  prepareProof,
  completeProof,
  verifyProof,
} from "@opencred/crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import { header, success, info, warn, json, separator, step } from "./helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Verify a raw signature against a public key (P-256, SHA-256 + ECDSA).
 * Returns true if valid.
 */
function verifyRaw(
  publicKeyObj: KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  const v = createVerify("SHA256");
  v.update(data);
  return v.verify(
    { key: publicKeyObj, dsaEncoding: "ieee-p1363" },
    signature,
  );
}

export async function main(): Promise<void> {
  header("Demo 09: All Signers — Unified Signer Interface");

  const signers: Array<{ signer: Signer; publicKeyObj: KeyObject }> = [];
  const testData = new TextEncoder().encode("OpenCred unified signer demo");

  // ── Step 1: Software signer from in-memory key buffer ────
  step(1, "Software signer from in-memory key buffer");

  const { privateKey: privKey1, publicKey: pubKey1 } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  const signer1 = buildSigner(privKey1, pubKey1, "in-memory-buffer");
  const sig1 = await signer1.sign(testData);

  info(`Signer ID: ${signer1.id}`);
  info(`Type: ${signer1.type} | Algorithm: ${signer1.algorithm}`);
  info(`Signature: ${sig1.length} bytes (raw r||s)`);

  const valid1 = verifyRaw(pubKey1, testData, sig1);
  if (!valid1) throw new Error("Step 1: signature verification failed");
  success("Software signer (buffer) — sign + verify OK");
  signers.push({ signer: signer1, publicKeyObj: pubKey1 });

  separator();

  // ── Step 2: Software signer from JWK file ────────────────
  step(2, "Software signer from JWK file");

  // Write a temporary JWK for this demo
  const tmpDir = resolve(__dirname, ".demo-tmp");
  mkdirSync(tmpDir, { recursive: true });
  const tmpJwkPath = resolve(tmpDir, "step2.jwk");

  const { privateKey: privKey2, publicKey: pubKey2 } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const jwk2 = privKey2.export({ format: "jwk" });
  writeFileSync(tmpJwkPath, JSON.stringify(jwk2));

  const { signer: signer2 } = createSoftwareSigner(tmpJwkPath, "jwk-file");
  const sig2 = await signer2.sign(testData);

  info(`Signer ID: ${signer2.id}`);
  info(`Type: ${signer2.type} | Algorithm: ${signer2.algorithm}`);
  info(`Signature: ${sig2.length} bytes (raw r||s)`);

  const valid2 = verifyRaw(pubKey2, testData, sig2);
  if (!valid2) throw new Error("Step 2: signature verification failed");
  success("Software signer (JWK file) — sign + verify OK");
  signers.push({ signer: signer2, publicKeyObj: pubKey2 });

  separator();

  // ── Step 3: PKCS#11 signer (SoftHSM) ────────────────────
  step(3, "PKCS#11 signer (SoftHSM)");

  let softhsmAvailable = false;
  const softhsmCandidates = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/libsofthsm2.dylib",
    "/opt/homebrew/lib/libsofthsm2.dylib",
  ];

  let softhsmLib: string | undefined;
  for (const p of softhsmCandidates) {
    if (existsSync(p)) {
      softhsmLib = p;
      break;
    }
  }

  if (softhsmLib) {
    try {
      const { createPkcs11Signer, destroyPkcs11Signer } = await import("@opencred/signing/pkcs11-signer");
      const result = createPkcs11Signer({
        libraryPath: softhsmLib,
        pin: "1234",
        label: "softhsm-demo",
      });

      const sig3 = await result.signer.sign(testData);
      info(`Signer ID: ${result.signer.id}`);
      info(`Type: ${result.signer.type} | Algorithm: ${result.signer.algorithm}`);
      info(`Available keys on token: ${result.availableKeys.length}`);
      info(`Signature: ${sig3.length} bytes (raw r||s)`);

      success("PKCS#11 signer (SoftHSM) — sign OK");
      softhsmAvailable = true;

      destroyPkcs11Signer(result.session, result.pkcs11Instance);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      warn(`PKCS#11: could not initialise — ${msg}`);
      info("This is expected if SoftHSM has no P-256 key on the demo token.");
    }
  } else {
    warn("PKCS#11: skipped (SoftHSM not detected)");
    info("Install SoftHSM: brew install softhsm (macOS) or apt install softhsm2 (Linux)");
    info("Then run: ./demos/setup-demo.sh to initialise the demo token");
  }

  separator();

  // ── Step 4: OS Certificate Store signer ──────────────────
  step(4, "OS Certificate Store signer");

  try {
    const { listOsCertificates } = await import("@opencred/signing/os-cert-signer");
    const platform = process.platform as "darwin" | "win32" | "linux";
    const result = await listOsCertificates(platform);
    info(`Store: ${result.storeName}`);
    info(`Certificates found: ${result.certificates.length}`);
    if (result.certificates.length > 0) {
      json("First certificate", {
        subject: result.certificates[0].subject,
        issuer: result.certificates[0].issuer,
        algorithm: result.certificates[0].keyAlgorithm,
      });
      success("OS Certificate Store — listing OK");
    } else {
      warn("OS Certificate Store: no P-256 signing certificates found");
      info("This is expected — OS cert signing requires a P-256 certificate installed in the system store");
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    warn(`OS Cert: skipped (native addon not available)`);
    info(`Detail: ${msg}`);
    info("The native addon (macos-keychain.node / windows-cng.node) must be compiled for OS cert signing");
  }

  separator();

  // ── Step 5: Unified interface — credential round-trip ────
  step(5, "Unified Signer interface — credential round-trip");

  info(`Active signers: ${signers.length} (software backends)`);
  if (softhsmAvailable) {
    info("PKCS#11 signer was available but excluded from credential round-trip (no public key export)");
  }

  for (const { signer, publicKeyObj } of signers) {
    info(`\n  Signing credential with: ${signer.metadata.label ?? signer.type}`);

    // Build an unsigned credential
    const unsignedVC = new CredentialBuilder()
      .addType("UniversityDegreeCredential")
      .setIssuer("did:web:university.example")
      .setCredentialSubject({
        id: "did:example:holder123",
        name: "Demo Student",
        degree: "BSc Computer Science",
        institution: "Demo University",
      })
      .setValidFrom("2026-01-01T00:00:00Z")
      .setValidUntil("2030-12-31T23:59:59Z")
      .build();

    // Phase 1: prepare proof (server-side)
    const prepared = await prepareProof(unsignedVC, {
      verificationMethod: signer.id,
      proofPurpose: "assertionMethod",
    });

    // Phase 2: sign with the Signer interface (could be any backend)
    const signatureBytes = await signer.sign(prepared.dataToSign);

    // Phase 3: assemble final credential
    const signedVC = completeProof(unsignedVC, prepared.proofConfig, signatureBytes);

    // Verify
    const result = await verifyProof(signedVC, { publicKey: publicKeyObj });
    if (!result.verified) {
      throw new Error(`Verification failed for signer ${signer.type}: ${result.error}`);
    }

    success(`  ${signer.metadata.label ?? signer.type}: prepareProof → sign → completeProof → verify ✓`);
  }

  separator();

  // Clean up temp files
  try {
    const { rmSync } = await import("node:fs");
    rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }

  success("Demo 09 complete — all available signers exercised through unified Signer interface");
}

const isDirectRun = !process.argv[1]?.includes("run-all");
if (isDirectRun) main().catch(console.error);
