/**
 * Batch issuance engine for the server (no Electron dependencies).
 *
 * Processes valid CSV rows through the credential issuance pipeline:
 * validate → build → sign → track progress.
 *
 * SECURITY INVARIANTS:
 *  - The signing key stays in-process — never transmitted.
 *  - Key material is NEVER logged.
 */

import { randomUUID, createHash } from "node:crypto";
import { CredentialBuilder } from "@opencred/vc-core";
import type { VerifiableCredential } from "@opencred/vc-core";
import { createRegistry, Validator } from "@opencred/schema-engine";
import type { SchemaRegistry } from "@opencred/schema-engine";
import {
  prepareVcJwtProof,
  completeVcJwtProof,
  prepareProof,
  completeProof,
  prepareEdDsaProof,
  completeEdDsaProof,
  prepareSdJwtVcProof,
  completeSdJwtVcProof,
} from "@opencred/crypto";
import type { Signer } from "@opencred/signing";
import type { ParsedRow } from "./csv-parser.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BatchRowStatus = "pending" | "processing" | "success" | "error" | "skipped";

export interface BatchRowResult {
  rowIndex: number;
  status: BatchRowStatus;
  error?: string;
  credential?: VerifiableCredential | string;
  isCompactToken?: boolean;
}

export interface BatchProgress {
  total: number;
  completed: number;
  successCount: number;
  errorCount: number;
  skippedCount: number;
  rows: BatchRowResult[];
  running: boolean;
  cancelled: boolean;
}

export type ProofFormat = "vc-jwt" | "data-integrity" | "sd-jwt-vc";

export interface BatchConfig {
  schemaId: string;
  issuerDid: string;
  validFrom: string;
  validUntil?: string;
  revocationRegistryUrl?: string;
  additionalTypes?: string[];
  proofFormat?: ProofFormat;
  selectiveDisclosureClaims?: string[];
  credentialSchemaUrl?: string;
}

// Singleton schema registry and validator
let registryInstance: SchemaRegistry | null = null;
let validatorInstance: Validator | null = null;

function getRegistry(): SchemaRegistry {
  if (!registryInstance) registryInstance = createRegistry();
  return registryInstance;
}

function getValidator(): Validator {
  if (!validatorInstance) validatorInstance = new Validator(getRegistry());
  return validatorInstance;
}

/**
 * Resolve the canonical schema URL (`$id`) for a registered built-in schema.
 * See the matching helper in `routes/credentials.ts` for rationale.
 */
function getBuiltInSchemaUrl(schemaId: string): string | undefined {
  try {
    const def = getRegistry().getSchema(schemaId);
    const id = (def.schema as { $id?: unknown })["$id"];
    return typeof id === "string" ? id : undefined;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Batch engine
// ---------------------------------------------------------------------------

export function createBatchEngine(signer: Signer, parsedRows: ParsedRow[], config: BatchConfig) {
  const progress: BatchProgress = {
    total: parsedRows.length,
    completed: 0,
    successCount: 0,
    errorCount: 0,
    skippedCount: 0,
    rows: parsedRows.map((row) => ({
      rowIndex: row.rowIndex,
      status: row.valid ? ("pending" as const) : ("skipped" as const),
      error: row.valid ? undefined : row.errors.map((e) => `${e.field}: ${e.message}`).join("; "),
    })),
    running: false,
    cancelled: false,
  };

  progress.skippedCount = progress.rows.filter((r) => r.status === "skipped").length;
  progress.completed = progress.skippedCount;

  async function processRow(parsedRow: ParsedRow, rowResult: BatchRowResult): Promise<void> {
    rowResult.status = "processing";

    try {
      // Validate
      getValidator().validateOrThrow(
        config.schemaId,
        parsedRow.mappedSubject as Record<string, unknown>,
      );

      // Build
      const builder = new CredentialBuilder()
        .setIssuer(config.issuerDid)
        .setValidFrom(config.validFrom);

      builder.setCredentialSubject(parsedRow.mappedSubject as Record<string, unknown>);

      if (config.additionalTypes) {
        for (const type of config.additionalTypes) builder.addType(type);
      }
      if (config.validUntil) builder.setValidUntil(config.validUntil);
      if (config.revocationRegistryUrl) {
        const credentialUuid = randomUUID();
        builder.setId(`urn:uuid:${credentialUuid}`);
        const revocationHash = createHash("sha256").update(credentialUuid).digest("hex");
        const statusListCredential = config.revocationRegistryUrl;
        const lookupUrl = statusListCredential.replace("/dedi/query/", "/dedi/lookup/");
        builder.setCredentialStatus({
          id: `${lookupUrl}/${revocationHash}`,
          type: "dedi",
          statusPurpose: "revocation",
          statusListCredential,
        });
      }
      // Default credentialSchema to the built-in schema's `$id` so every issued
      // credential carries a stable schema URL. User-provided URL still wins.
      const credentialSchemaUrl =
        config.credentialSchemaUrl ?? getBuiltInSchemaUrl(config.schemaId);
      if (credentialSchemaUrl) {
        builder.setSchema({ id: credentialSchemaUrl, type: "JsonSchema" });
      }

      const unsigned = builder.build();
      const proofFormat = config.proofFormat ?? "vc-jwt";
      const vct = config.additionalTypes?.[0] ?? config.schemaId;

      // Sign
      switch (proofFormat) {
        case "vc-jwt": {
          const vcAsRecord = unsigned as unknown as Record<string, unknown>;
          const { signingInput } = prepareVcJwtProof(vcAsRecord, signer.algorithm, {
            verificationMethod: signer.id,
          });
          const dataToSign = new TextEncoder().encode(signingInput);
          const signatureBytes = await signer.sign(dataToSign);
          const jwt = completeVcJwtProof(signingInput, signatureBytes);
          rowResult.credential = {
            ...unsigned,
            proof: { type: "JsonWebSignature2020", jwt },
          } as unknown as VerifiableCredential;
          rowResult.isCompactToken = false;
          break;
        }
        case "data-integrity": {
          const proofOptions = { verificationMethod: signer.id, proofPurpose: "assertionMethod" };
          if (signer.algorithm === "Ed25519") {
            const { dataToSign, proofConfig } = await prepareEdDsaProof(unsigned, proofOptions);
            const signatureBytes = await signer.sign(dataToSign);
            rowResult.credential = completeEdDsaProof(unsigned, proofConfig, signatureBytes);
          } else {
            const { dataToSign, proofConfig } = await prepareProof(
              unsigned,
              proofOptions,
              signer.algorithm as "P-256" | "P-384",
            );
            const signatureBytes = await signer.sign(dataToSign);
            rowResult.credential = completeProof(unsigned, proofConfig, signatureBytes);
          }
          rowResult.isCompactToken = false;
          break;
        }
        case "sd-jwt-vc": {
          const sdJwtOptions = {
            selectiveDisclosureClaims: config.selectiveDisclosureClaims ?? [],
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
          rowResult.credential = completeSdJwtVcProof(signingInput, signatureBytes, disclosures);
          rowResult.isCompactToken = true;
          break;
        }
      }

      rowResult.status = "success";
      progress.successCount++;
    } catch (err) {
      rowResult.status = "error";
      rowResult.error = err instanceof Error ? err.message : "Unknown signing error";
      progress.errorCount++;
    }

    progress.completed++;
  }

  return {
    async start(): Promise<BatchProgress> {
      progress.running = true;
      progress.cancelled = false;

      for (let i = 0; i < parsedRows.length; i++) {
        if (progress.cancelled) {
          for (let j = i; j < parsedRows.length; j++) {
            const rowResult = progress.rows[j];
            if (rowResult.status === "pending") {
              rowResult.status = "skipped";
              rowResult.error = "Batch cancelled";
              progress.skippedCount++;
              progress.completed++;
            }
          }
          break;
        }

        const parsedRow = parsedRows[i];
        const rowResult = progress.rows[i];

        if (!parsedRow.valid || rowResult.status === "skipped") continue;
        await processRow(parsedRow, rowResult);
      }

      progress.running = false;
      return { ...progress, rows: [...progress.rows] };
    },

    cancel(): void {
      progress.cancelled = true;
    },

    getProgress(): BatchProgress {
      return { ...progress, rows: [...progress.rows] };
    },
  };
}

export type BatchEngine = ReturnType<typeof createBatchEngine>;
