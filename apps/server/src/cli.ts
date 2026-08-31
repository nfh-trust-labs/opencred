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
  prepareJws2020Proof,
  completeJws2020Proof,
  isCanonicalizingProofFormat,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
  sha256Hex,
} from "@opencred/crypto";
import { createSoftwareSigner } from "@opencred/signing";
import type { Signer } from "@opencred/signing";
import { encodeDidWeb } from "@opencred/did";
import type { TemplateCustomization } from "@opencred/templates";
import { loadConfig, resetConfig } from "./config.js";
import type { ServerConfig } from "./config.js";
import { parseCsv } from "./batch/csv-parser.js";
import { createBatchEngine } from "./batch/batch-engine.js";
import type { ProofFormat } from "./batch/batch-engine.js";
import { setSchemaRegistry } from "./schema-registry-singleton.js";
import { setValidator } from "./validator-singleton.js";

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

/**
 * Resolve the issuer DID for a CLI invocation.
 *
 * Priority:
 *   1. `OPENCRED_ISSUER_DID_METHOD=web` + `OPENCRED_ISSUER_DOMAIN`
 *      → `did:web:<domain>` (operator opt-in)
 *   2. Otherwise → signer-derived DID (`did:key:z…` for EC/Ed25519,
 *      `did:jwk:…` for RSA), stripped of its `#fragment`
 *
 * The CLI deliberately reads `process.env` directly instead of calling
 * `loadConfig()` — `loadConfig` enforces the server's auth-fail-closed
 * invariant (requires OPENCRED_API_KEY), which is irrelevant when running
 * the CLI standalone for one-shot issuance. The two issuer-identity env
 * vars are safe to read individually because they only affect the DID
 * shape, not any security boundary.
 *
 * Callers may still layer an `input.issuerDid` override on top of this
 * default (see the `issue` command).
 */
function resolveConfiguredIssuerDid(signer: Signer): string {
  const method = process.env.OPENCRED_ISSUER_DID_METHOD;
  const rawDomain = process.env.OPENCRED_ISSUER_DOMAIN;
  const domain = rawDomain?.trim();
  if (method === "web") {
    if (!domain) {
      throw new Error(
        "OPENCRED_ISSUER_DOMAIN is required when OPENCRED_ISSUER_DID_METHOD=web. " +
          "Set it to your did:web domain (e.g. 'issuer.example.com') or unset " +
          "OPENCRED_ISSUER_DID_METHOD to use the signer-derived did:key.",
      );
    }
    return encodeDidWeb(domain);
  }
  return signer.id.split("#")[0];
}

function readJsonInput(inputPath: string): Record<string, unknown> {
  const absPath = resolve(inputPath);
  const content = readFileSync(absPath, "utf-8");
  return JSON.parse(content) as Record<string, unknown>;
}

/**
 * Read an image file and convert it to a data URI.
 * Only image files are accepted (png, jpg, jpeg, gif, svg, webp).
 */
function readLogoAsDataUri(logoPath: string): string {
  const absPath = resolve(logoPath);
  const ext = absPath.split(".").pop()?.toLowerCase() ?? "";
  const mimeMap: Record<string, string> = {
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    svg: "image/svg+xml",
    webp: "image/webp",
  };
  const mime = mimeMap[ext];
  if (!mime) {
    throw new Error(
      `Unsupported logo file type: .${ext}. Supported: ${Object.keys(mimeMap).join(", ")}`,
    );
  }
  const data = readFileSync(absPath);
  return `data:${mime};base64,${data.toString("base64")}`;
}

/**
 * Build a TemplateCustomization from CLI flag values.
 * Returns undefined if no branding flags were provided.
 */
function buildCustomization(opts: {
  primaryColor?: string;
  logo?: string;
  issuerName?: string;
}): TemplateCustomization | undefined {
  if (!opts.primaryColor && !opts.logo && !opts.issuerName) return undefined;

  const customization: TemplateCustomization = {};
  if (opts.primaryColor) {
    if (!/^#[0-9a-fA-F]{6}$/.test(opts.primaryColor)) {
      throw new Error("--primary-color must be a 6-digit hex color (e.g. #1a56db)");
    }
    customization.primaryColor = opts.primaryColor;
  }
  if (opts.logo) {
    customization.logoDataUri = readLogoAsDataUri(opts.logo);
  }
  if (opts.issuerName) {
    customization.issuerDisplayName = opts.issuerName;
  }
  return customization;
}

type CliProofFormat = "vc-jwt" | "data-integrity" | "jws-2020" | "sd-jwt-vc";

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

    case "jws-2020": {
      // JsonWebSignature2020 embedded proof — detached RFC 7797 JWS over the
      // canonicalized credential. Works with all key algorithms.
      const prepared = await prepareJws2020Proof(unsigned, signer.algorithm, {
        verificationMethod: signer.id,
        proofPurpose: "assertionMethod",
      });
      const signatureBytes = await signer.sign(prepared.dataToSign);
      const signedCredential = completeJws2020Proof(prepared, signatureBytes);
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
// Verify command — supports JSON-LD VC, vc-jwt, sd-jwt-vc, PixelPass QR
// data, and PDF input. The implementation lives here (not inline in the
// action handler) so tests can exercise it without going through commander.
// ---------------------------------------------------------------------------

export interface VerifyCliResult {
  /** Top-level outcome — drives the CLI exit code. */
  verified: boolean;
  /** Stable enum from `@opencred/verification`. */
  code: string;
  /** Per-check breakdown straight from the verifier (no sanitization). */
  checks: Array<{ name: string; passed: boolean; detail?: string }>;
  /** Detected input shape. Useful for `--json` consumers. */
  inputFormat: "pdf" | "pixelpass" | "json" | "jwt-compact" | "unknown";
  /** Resolved input path, or `<stdin>`. */
  source: string;
}

export async function runVerify(opts: {
  input: string;
  cscaTrustStorePath?: string;
}): Promise<VerifyCliResult> {
  const { input, cscaTrustStorePath } = opts;
  // Read-from-stdin convention: `--input -` means "read all of stdin".
  // Stdin is buffered as bytes so we don't lose binary PDFs piped in via
  // process substitution. The buffer is then either treated as a PDF (if
  // it has the `%PDF-` magic) or decoded as UTF-8 for the text-shaped
  // formats — same dispatch the file-path branch uses, so the behavior
  // is symmetric.
  const { isPdfBytes, detectCredentialInputFormat } = await import("@opencred/shared");

  const sourceLabel = input === "-" ? "<stdin>" : resolve(input);
  const bytes: Buffer = input === "-" ? await readAllStdinBytes() : readFileSync(resolve(input));

  const { CompositeDIDResolver, DIDKeyResolver, DIDJwkResolver, DIDWebResolver } =
    await import("@opencred/did");
  const { verifyCredential, verifyPdf, loadCscaTrustStore } =
    await import("@opencred/verification");

  // DeDi-backed did:web fallback. When OPENCRED_DEDI_* env vars are set,
  // build a DeDi client and use it as the resolver fallback so the CLI
  // can verify credentials whose issuer's `.well-known/did.json` is
  // unreachable but whose DID document has been published to DeDi via
  // `POST /v1/keys/publish`. The server route and the desktop IPC do
  // the equivalent wiring.
  const dediBaseUrl = process.env.OPENCRED_DEDI_BASE_URL;
  let didWebResolver: InstanceType<typeof DIDWebResolver>;
  if (dediBaseUrl) {
    const { DeDiClient, createDeDiDIDWebFallback } = await import("@opencred/dedi-client");
    const authType = process.env.OPENCRED_DEDI_AUTH_TYPE ?? "api-key";
    const auth =
      authType === "bearer"
        ? ({
            type: "bearer" as const,
            email: process.env.OPENCRED_DEDI_EMAIL ?? "",
            password: process.env.OPENCRED_DEDI_PASSWORD ?? "",
          } as const)
        : ({
            type: "api-key" as const,
            apiKey: process.env.OPENCRED_DEDI_API_KEY ?? "",
          } as const);
    // Mirror OPENCRED_DEDI_MAX_RETRIES (see config.ts) on the CLI verify path,
    // which wires the DeDi client from process.env directly. Clamp to the same
    // [0, 5] bound; fall back to the default of 2 for unset/invalid values.
    const parsedRetries = Number.parseInt(process.env.OPENCRED_DEDI_MAX_RETRIES ?? "", 10);
    const dediMaxRetries = Number.isInteger(parsedRetries)
      ? Math.min(5, Math.max(0, parsedRetries))
      : 2;
    const dediClient = new DeDiClient({
      baseUrl: dediBaseUrl,
      auth,
      defaultNamespace: process.env.OPENCRED_DEDI_NAMESPACE ?? "",
      timeoutMs: 10_000,
      circuitBreakerThreshold: 5,
      maxRetries: dediMaxRetries,
    });
    didWebResolver = new DIDWebResolver(createDeDiDIDWebFallback(dediClient));
  } else {
    didWebResolver = new DIDWebResolver();
  }

  const compositeResolver = new CompositeDIDResolver(
    new Map([
      ["key", new DIDKeyResolver()],
      ["jwk", new DIDJwkResolver()],
      ["web", didWebResolver],
    ]),
  );
  const trustAnchors = cscaTrustStorePath
    ? await loadCscaTrustStore(resolve(cscaTrustStorePath))
    : undefined;
  const config = { didResolver: compositeResolver, trustAnchors };

  // PDF branch: magic-byte check up front. We do this before any UTF-8
  // decode so a binary PDF whose bytes happen to include invalid UTF-8
  // sequences doesn't fall into the "unknown format" path.
  if (isPdfBytes(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength))) {
    const result = await verifyPdf(bytes, config);
    return {
      verified: result.verified,
      code: result.code,
      checks: [...result.checks],
      inputFormat: "pdf",
      source: sourceLabel,
    };
  }

  // Text-shaped branches: classify and dispatch the same way the
  // `/v1/credentials/verify` JSON branch does.
  const text = bytes.toString("utf-8").trim();
  const format = detectCredentialInputFormat(text);

  if (format === "unknown") {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "cli-input",
          passed: false,
          detail:
            "Could not classify input as JSON-LD, vc-jwt, sd-jwt-vc, PixelPass QR data, or PDF.",
        },
      ],
      inputFormat: "unknown",
      source: sourceLabel,
    };
  }

  let credentialForVerify: Record<string, unknown> | string;
  if (format === "pixelpass") {
    const { decodePixelPass } = await import("@opencred/verification");
    credentialForVerify = JSON.parse(decodePixelPass(text));
  } else if (format === "json") {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    // VC-JWT envelope unwrap: the issuance side (server's
    // `/credentials/issue` and the desktop sign flow) wraps a vc-jwt
    // signed token in `{ ..., proof: { type: "JsonWebSignature2020",
    // jwt: "eyJ..." } }`. The verification engine expects the bare
    // compact token, not the envelope. Detect and unwrap, mirroring the
    // desktop IPC handler at `apps/desktop/src/main/ipc-handlers.ts`.
    const proof = parsed.proof as Record<string, unknown> | undefined;
    if (proof && typeof proof.jwt === "string") {
      credentialForVerify = proof.jwt;
    } else {
      credentialForVerify = parsed;
    }
  } else {
    // jwt-compact — pass through unchanged.
    credentialForVerify = text;
  }

  const result = await verifyCredential(credentialForVerify, config);
  return {
    verified: result.verified,
    code: result.code,
    checks: [...result.checks],
    inputFormat: format,
    source: sourceLabel,
  };
}

async function readAllStdinBytes(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

function printVerifyResultHuman(result: VerifyCliResult): void {
  const banner = result.verified
    ? `VALID — credential verified (${result.code}, format: ${result.inputFormat})`
    : `INVALID — ${result.code} (format: ${result.inputFormat})`;
  console.log(banner);
  console.log(`source: ${result.source}`);
  console.log("checks:");
  for (const check of result.checks) {
    const status = check.passed ? "PASS" : "FAIL";
    const detail = check.detail ? ` — ${check.detail}` : "";
    console.log(`  [${status}] ${check.name}${detail}`);
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
    .option(
      "--proof-format <format>",
      "Proof format: vc-jwt, data-integrity, jws-2020, sd-jwt-vc",
      "vc-jwt",
    )
    .requiredOption("--output <file>", "Output file path for the signed credential")
    .option("--primary-color <hex>", "Primary branding color (e.g. #1a56db)")
    .option("--logo <file>", "Path to issuer logo image file (PNG/JPG/SVG)")
    .option("--issuer-name <name>", "Issuer display name (overrides DID in output)")
    .action(async (opts) => {
      const signer = loadKey(opts.key);
      const input = readJsonInput(opts.input);
      const customization = buildCustomization(opts);
      if (customization) {
        console.log("Branding customization loaded (will apply to packaged output).");
      }

      const registry = createRegistry();
      const validator = new Validator(registry);

      const subject = (input.credentialSubject ?? input) as Record<string, unknown>;
      validator.validateOrThrow(opts.schema, subject);

      const issuerDid = (input.issuerDid as string) ?? resolveConfiguredIssuerDid(signer);
      const validFrom = (input.validFrom as string) ?? new Date().toISOString();

      const builder = new CredentialBuilder()
        .setIssuer(issuerDid)
        .setValidFrom(validFrom)
        .setCredentialSubject(subject);

      if (input.validUntil) builder.setValidUntil(input.validUntil as string);
      if (input.additionalTypes) {
        for (const t of input.additionalTypes as string[]) builder.addType(t);
      }

      const proofFormat = opts.proofFormat as CliProofFormat;
      // Canonicalizing proof formats (data-integrity / jws-2020) need every
      // credential term defined in a loaded JSON-LD context — attach the
      // schema's registered context, mirroring /v1/credentials/issue.
      if (isCanonicalizingProofFormat(proofFormat)) {
        const contextUrl = registry.getContextForType(opts.schema);
        if (contextUrl) builder.addContext(contextUrl);
      }

      const unsigned = builder.build();
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
        "  Accepts any of the formats produced by `opencred issue` and the\n" +
        "  Docker server's /v1/credentials/issue endpoint:\n" +
        "    - JSON-LD VC (.json / .jsonld)\n" +
        "    - vc-jwt or sd-jwt-vc compact token (text file)\n" +
        "    - PixelPass-compressed QR data (bare Base45 payload)\n" +
        "    - OpenCred-issued PDF certificate (.pdf)\n\n" +
        "  Reads from --input, or from stdin when --input is `-`.\n\n" +
        "  Examples:\n" +
        "    $ opencred verify --input cred.json\n" +
        "    $ opencred verify --input certificate.pdf\n" +
        "    $ cat token.jwt | opencred verify --input -\n" +
        "    $ opencred verify --input cred.json --json",
    )
    .requiredOption("--input <file>", "Path to the credential file (or `-` for stdin)")
    .option("--json", "Emit the full verification result as JSON")
    .option(
      "--csca-trust-store <dir>",
      "Path to a directory of PEM CSCA roots (required for x5c-bearing credentials)",
    )
    .action(async (opts) => {
      const result = await runVerify({
        input: opts.input as string,
        cscaTrustStorePath: opts.cscaTrustStore as string | undefined,
      });

      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printVerifyResultHuman(result);
      }
      process.exit(result.verified ? 0 : 1);
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
    .option(
      "--proof-format <format>",
      "Proof format: vc-jwt, data-integrity, jws-2020, sd-jwt-vc",
      "vc-jwt",
    )
    .option("--primary-color <hex>", "Primary branding color (e.g. #1a56db)")
    .option("--logo <file>", "Path to issuer logo image file (PNG/JPG/SVG)")
    .option("--issuer-name <name>", "Issuer display name (overrides DID in output)")
    .action(async (opts) => {
      const signer = loadKey(opts.key);
      const csvContent = readFileSync(resolve(opts.input), "utf-8");
      const outputDir = resolve(opts.outputDir);
      const customization = buildCustomization(opts);
      if (customization) {
        console.log("Branding customization loaded (will apply to packaged output).");
      }

      if (!existsSync(outputDir)) {
        mkdirSync(outputDir, { recursive: true });
      }

      // Bootstrap the process-wide registry + validator that parseCsv and
      // createBatchEngine expect. The CLI previously relied on
      // getSchemaRegistry()'s silent lazy-create fallback; that fallback was
      // removed for P1-01 so the bootstrap is now explicit here.
      const batchRegistry = createRegistry();
      setSchemaRegistry(batchRegistry);
      setValidator(new Validator(batchRegistry));

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
        issuerDid: resolveConfiguredIssuerDid(signer),
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

  const configCmd = program.command("config").description("Configuration management commands");

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
          config.OPENCRED_KMS_PROVIDER === "none" ? "file-based" : config.OPENCRED_KMS_PROVIDER;

        console.log(
          `Configuration valid (port: ${config.OPENCRED_PORT}, auth: ${authMode}, kms: ${kms})`,
        );
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`Configuration error: ${message}`);
        process.exit(1);
      }
    });

  // -------------------------------------------------------------------------
  // identity command group
  // -------------------------------------------------------------------------

  const identityCmd = program
    .command("identity")
    .description("Inspect issuer identity (DID method, derived DID, key source)");

  identityCmd
    .command("show")
    .description(
      "Print the configured issuer DID and key source\n\n" +
        "  Resolves the issuer DID using the same logic as the issue/batch\n" +
        "  commands and prints it alongside the key file metadata. Useful\n" +
        "  for verifying that the configured DID matches what verifiers will\n" +
        "  see in issued credentials.\n\n" +
        "  Required: --key <path> (or OPENCRED_KEY_PATH).\n\n" +
        "  Examples:\n" +
        "    $ opencred identity show --key ./issuer.pem\n" +
        "    $ OPENCRED_ISSUER_DID_METHOD=web OPENCRED_ISSUER_DOMAIN=issuer.example.com \\\n" +
        "        opencred identity show --key ./issuer.pem",
    )
    .option(
      "--key <pem-path>",
      "Path to signing key file (PEM/JWK/PFX). Defaults to $OPENCRED_KEY_PATH.",
    )
    .action((opts: { key?: string }) => {
      const keyPath = opts.key ?? process.env.OPENCRED_KEY_PATH;
      if (!keyPath) {
        console.error(
          "No key specified. Pass --key <path> or set OPENCRED_KEY_PATH in the environment.",
        );
        process.exit(1);
      }
      const signer = loadKey(keyPath);
      const method = process.env.OPENCRED_ISSUER_DID_METHOD ?? "key";
      const domain = process.env.OPENCRED_ISSUER_DOMAIN;
      const issuerDid = resolveConfiguredIssuerDid(signer);
      const dediConfigured = !!process.env.OPENCRED_DEDI_BASE_URL;
      const dediHostsDoc = process.env.OPENCRED_DEDI_HOST_DID_DOC === "true";

      console.log("Issuer identity:");
      console.log(`  DID method:        ${method}`);
      if (method === "web") {
        console.log(`  Domain:            ${domain ?? "(unset — required for did:web)"}`);
      }
      console.log(`  Issuer DID:        ${issuerDid}`);
      console.log(`  Verification ID:   ${signer.id}`);
      console.log(`  Algorithm:         ${signer.algorithm}`);
      console.log(`  Key fingerprint:   ${signer.metadata.fingerprint}`);
      console.log(`  Key source:        ${signer.type}`);
      console.log(
        `  DeDi:              ${
          dediConfigured
            ? `configured${dediHostsDoc ? " (hosts DID doc)" : " (revocation/attribution only)"}`
            : "not configured"
        }`,
      );
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
