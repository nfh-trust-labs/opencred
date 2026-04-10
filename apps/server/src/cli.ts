#!/usr/bin/env node
/**
 * OpenCred CLI — command-line interface for credential operations.
 *
 * Commands:
 *   opencred issue            — issue a single Verifiable Credential
 *   opencred verify           — verify a signed Verifiable Credential
 *   opencred hash             — compute SHA-256 hash of a credential
 *   opencred batch            — batch-issue credentials from a CSV file
 *   opencred config validate  — validate server configuration
 *
 * Each command calls shared packages directly (no HTTP server).
 *
 * SECURITY INVARIANTS:
 *  - Signing keys are loaded from local files — never transmitted.
 *  - Key material is NEVER logged or printed to stdout.
 *  - JSON-LD contexts are bundled — no remote fetching.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { CredentialBuilder } from "@opencred/vc-core";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import { createRegistry, Validator } from "@opencred/schema-engine";
import {
  prepareVcJwtProof,
  completeVcJwtProof,
  prepareProof,
  completeProof,
  prepareEdDsaProof,
  completeEdDsaProof,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
  verifyProof,
  sha256Hex,
} from "@opencred/crypto";
import { publicKeyFromMultibase } from "@opencred/verification";
import { createSoftwareSigner } from "@opencred/signing";
import type { Signer } from "@opencred/signing";
import { loadConfig, resetConfig } from "./config.js";
import type { ServerConfig } from "./config.js";
import { parseCsv } from "./batch/csv-parser.js";
import { createBatchEngine } from "./batch/batch-engine.js";
import type { ProofFormat } from "./batch/batch-engine.js";

// ---------------------------------------------------------------------------
// Version — read from package.json at the package root
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function readVersion(): string {
  // Works from both src/ (ts-node/tsx) and dist/ (compiled JS)
  const pkgPath = join(__dirname, "..", "package.json");
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as { version: string };
    return pkg.version;
  } catch {
    return "0.0.0";
  }
}

export const VERSION = readVersion();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadKey(keyPath: string): Signer {
  const absPath = resolve(keyPath);
  const { signer } = createSoftwareSigner(absPath);
  return signer;
}

function readJsonInput(inputPath: string): Record<string, unknown> {
  const absPath = resolve(inputPath);
  const content = readFileSync(absPath, "utf-8");
  return JSON.parse(content) as Record<string, unknown>;
}

type CliProofFormat = "vc-jwt" | "data-integrity" | "sd-jwt-vc";

async function signCredential(
  unsigned: UnsignedCredential,
  signer: Signer,
  proofFormat: CliProofFormat,
  schemaId: string,
): Promise<string> {
  const vct = schemaId;

  switch (proofFormat) {
    case "vc-jwt": {
      const vcAsRecord = unsigned as unknown as Record<string, unknown>;
      const { signingInput } = prepareVcJwtProof(vcAsRecord, signer.algorithm, {
        verificationMethod: signer.id,
      });
      const dataToSign = new TextEncoder().encode(signingInput);
      const signatureBytes = await signer.sign(dataToSign);
      const jwt = completeVcJwtProof(signingInput, signatureBytes);
      const signedCredential = {
        ...unsigned,
        proof: { type: "JsonWebSignature2020", jwt },
      };
      return JSON.stringify(signedCredential, null, 2);
    }

    case "data-integrity": {
      const proofOptions = {
        verificationMethod: signer.id,
        proofPurpose: "assertionMethod",
      };

      let signedCredential: VerifiableCredential;

      if (signer.algorithm === "Ed25519") {
        const { dataToSign, proofConfig } = await prepareEdDsaProof(unsigned, proofOptions);
        const signatureBytes = await signer.sign(dataToSign);
        signedCredential = completeEdDsaProof(unsigned, proofConfig, signatureBytes);
      } else {
        const { dataToSign, proofConfig } = await prepareProof(
          unsigned,
          proofOptions,
          signer.algorithm as "P-256" | "P-384",
        );
        const signatureBytes = await signer.sign(dataToSign);
        signedCredential = completeProof(unsigned, proofConfig, signatureBytes);
      }

      return JSON.stringify(signedCredential, null, 2);
    }

    case "sd-jwt-vc": {
      const sdJwtOptions = {
        selectiveDisclosureClaims: [] as string[],
        vct,
        verificationMethod: signer.id,
      };

      const { signingInput, disclosures } = prepareSdJwtVcProof(
        unsigned,
        signer.algorithm,
        sdJwtOptions,
      );
      const dataToSign = new TextEncoder().encode(signingInput);
      const signatureBytes = await signer.sign(dataToSign);
      return completeSdJwtVcProof(signingInput, signatureBytes, disclosures);
    }
  }
}

// ---------------------------------------------------------------------------
// Program factory — exported for testing
// ---------------------------------------------------------------------------

/**
 * Create and return the fully configured CLI program. Exported so tests can
 * invoke subcommands in-process without spawning a subprocess.
 */
export function createProgram(): Command {
  const program = new Command();

  program
    .name("opencred")
    .description(
      "OpenCred CLI — Verifiable Credential operations\n\n" +
        "Examples:\n" +
        "  $ opencred issue --schema education --input data.json --key key.pem --output cred.json\n" +
        "  $ opencred verify --input cred.json\n" +
        "  $ opencred hash --input cred.json\n" +
        "  $ opencred batch --schema education --input data.csv --key key.pem --output-dir ./creds/\n" +
        "  $ opencred config validate",
    )
    .version(VERSION, "-v, --version");

  // -------------------------------------------------------------------------
  // issue command
  // -------------------------------------------------------------------------

  program
    .command("issue")
    .description(
      "Issue a single Verifiable Credential\n\n" +
        "  Example:\n" +
        "    $ opencred issue --schema education --input data.json --key key.pem --output cred.json",
    )
    .requiredOption("--schema <id>", "Schema ID to validate against")
    .requiredOption("--input <file>", "JSON file with credentialSubject data")
    .requiredOption("--key <pem-path>", "Path to signing key file (PEM/JWK/PFX)")
    .option("--proof-format <format>", "Proof format: vc-jwt, data-integrity, sd-jwt-vc", "vc-jwt")
    .requiredOption("--output <file>", "Output file path for the signed credential")
    .action(async (opts) => {
      const signer = loadKey(opts.key);
      const input = readJsonInput(opts.input);

      const registry = createRegistry();
      const validator = new Validator(registry);

      const subject = (input.credentialSubject ?? input) as Record<string, unknown>;
      validator.validateOrThrow(opts.schema, subject);

      const issuerDid = (input.issuerDid as string) ?? signer.id.split("#")[0];
      const validFrom = (input.validFrom as string) ?? new Date().toISOString();

      const builder = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setValidFrom(validFrom)
        .setCredentialSubject(subject);

      if (input.validUntil) builder.setValidUntil(input.validUntil as string);
      if (input.additionalTypes) {
        for (const t of input.additionalTypes as string[]) builder.addType(t);
      }

      const unsigned = builder.build();
      const proofFormat = opts.proofFormat as CliProofFormat;
      const output = await signCredential(unsigned, signer, proofFormat, opts.schema);

      const outputPath = resolve(opts.output);
      writeFileSync(outputPath, output, "utf-8");
      console.log(`Credential written to ${outputPath}`);
    });

  // -------------------------------------------------------------------------
  // verify command
  // -------------------------------------------------------------------------

  program
    .command("verify")
    .description(
      "Verify a signed Verifiable Credential\n\n" +
        "  Example:\n" +
        "    $ opencred verify --input cred.json",
    )
    .requiredOption("--input <file>", "Path to the signed credential JSON file")
    .action(async (opts) => {
      const content = readFileSync(resolve(opts.input), "utf-8");
      const credential = JSON.parse(content);

      const proof = credential.proof;
      if (!proof || !proof.verificationMethod) {
        console.error("Credential is missing proof.verificationMethod");
        process.exit(1);
      }

      const vm: string = proof.verificationMethod;
      const fragment = vm.includes("#") ? vm.split("#")[1] : undefined;
      const publicKey = fragment ? (publicKeyFromMultibase(fragment) ?? undefined) : undefined;

      if (!publicKey) {
        console.error(
          "Unable to resolve public key from verificationMethod. Only did:key is supported.",
        );
        process.exit(1);
      }

      const result = await verifyProof(credential, { publicKey });

      if (result.verified) {
        console.log("VALID — Credential signature verified successfully.");
      } else {
        console.error(`INVALID — ${result.error ?? "Verification failed."}`);
        process.exit(1);
      }
    });

  // -------------------------------------------------------------------------
  // hash command
  // -------------------------------------------------------------------------

  program
    .command("hash")
    .description(
      "Compute SHA-256 hash of a credential file\n\n" +
        "  Example:\n" +
        "    $ opencred hash --input cred.json",
    )
    .requiredOption("--input <file>", "Path to the credential file")
    .action((opts) => {
      const content = readFileSync(resolve(opts.input));
      const hex = sha256Hex(content);
      console.log(hex);
    });

  // -------------------------------------------------------------------------
  // batch command
  // -------------------------------------------------------------------------

  program
    .command("batch")
    .description(
      "Batch-issue credentials from a CSV file\n\n" +
        "  Example:\n" +
        "    $ opencred batch --schema education --input data.csv --key key.pem --output-dir ./creds/",
    )
    .requiredOption("--schema <id>", "Schema ID to validate against")
    .requiredOption("--input <csv-file>", "CSV file with credential data")
    .requiredOption("--key <pem-path>", "Path to signing key file (PEM/JWK/PFX)")
    .requiredOption("--output-dir <dir>", "Output directory for issued credentials")
    .option("--proof-format <format>", "Proof format: vc-jwt, data-integrity, sd-jwt-vc", "vc-jwt")
    .action(async (opts) => {
      const signer = loadKey(opts.key);
      const csvContent = readFileSync(resolve(opts.input), "utf-8");
      const outputDir = resolve(opts.outputDir);

      if (!existsSync(outputDir)) {
        mkdirSync(outputDir, { recursive: true });
      }

      const parseResult = parseCsv(csvContent, { schemaId: opts.schema });

      console.log(
        `Parsed ${parseResult.totalCount} rows: ${parseResult.validCount} valid, ${parseResult.invalidCount} invalid`,
      );

      if (parseResult.validCount === 0) {
        console.error("No valid rows to process.");
        process.exit(1);
      }

      const engine = createBatchEngine(signer, parseResult.rows, {
        schemaId: opts.schema,
        issuerDid: signer.id.split("#")[0],
        validFrom: new Date().toISOString(),
        proofFormat: opts.proofFormat as ProofFormat,
      });

      const progress = await engine.start();

      let written = 0;
      for (const row of progress.rows) {
        if (row.status === "success" && row.credential) {
          const filename = `credential-${row.rowIndex}.json`;
          const content =
            typeof row.credential === "string"
              ? row.credential
              : JSON.stringify(row.credential, null, 2);
          writeFileSync(join(outputDir, filename), content, "utf-8");
          written++;
        }
      }

      console.log(
        `Batch complete: ${progress.successCount} issued, ${progress.errorCount} errors, ${progress.skippedCount} skipped`,
      );
      console.log(`${written} credentials written to ${outputDir}`);

      if (progress.errorCount > 0) {
        for (const row of progress.rows) {
          if (row.status === "error") {
            console.error(`  Row ${row.rowIndex}: ${row.error}`);
          }
        }
        process.exit(1);
      }
    });

  // -------------------------------------------------------------------------
  // config command group
  // -------------------------------------------------------------------------

  const configCmd = program
    .command("config")
    .description("Configuration management commands");

  configCmd
    .command("validate")
    .description(
      "Validate server configuration from environment variables\n\n" +
        "  Loads and validates all OPENCRED_* environment variables without\n" +
        "  starting the server. Useful for CI/CD pre-flight checks.\n\n" +
        "  Example:\n" +
        "    $ opencred config validate",
    )
    .action(() => {
      // Reset any cached config so we always re-read env vars
      resetConfig();
      try {
        const config: ServerConfig = loadConfig();

        const authMode = config.OPENCRED_API_KEY ? "enabled" : "dev-mode (no auth)";
        const kms =
          config.OPENCRED_KMS_PROVIDER === "none"
            ? "file-based"
            : config.OPENCRED_KMS_PROVIDER;

        console.log(
          `Configuration valid (port: ${config.OPENCRED_PORT}, auth: ${authMode}, kms: ${kms})`,
        );
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`Configuration error: ${message}`);
        process.exit(1);
      }
    });

  return program;
}

// ---------------------------------------------------------------------------
// Parse and run — only when executed directly (not when imported by tests)
// ---------------------------------------------------------------------------

const isDirectRun = process.argv[1] === __filename;

if (isDirectRun) {
  createProgram().parse();
}
