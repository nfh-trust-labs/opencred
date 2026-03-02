import { Hono } from "hono";
import { z } from "zod";
import { zValidator } from "@hono/zod-validator";
import { randomUUID } from "node:crypto";
import { parse as parseCsv } from "csv-parse/sync";
import { CredentialBuilder } from "@opencred/vc-core";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";
import {
  prepareProof,
  completeProof,
  signCredential,
  computeRevocationHash,
} from "@opencred/crypto";
import type { ProofConfig, SigningKeyProvider } from "@opencred/crypto";
import { createRegistry, Validator } from "@opencred/schema-engine";
import { TTLStore } from "@opencred/state";
import { ValidationError, SessionExpiredError, AuthorizationError } from "@opencred/shared";
import type { EnvConfig } from "@opencred/shared";
import type { DeDiClient } from "@opencred/dedi-client";
import {
  resolveDelegation,
  validateDelegationCertificate,
  embedDelegation,
} from "@opencred/delegation";
import { authMiddleware, type AuthMiddlewareOptions } from "../middleware/auth.js";
import { packageFormats } from "../output/index.js";
import type { PackagedFormats } from "../output/index.js";

// ---------------------------------------------------------------------------
// Request schemas
// ---------------------------------------------------------------------------

const credentialEntrySchema = z.object({
  credentialSubject: z.record(z.unknown()).refine((v) => Object.keys(v).length > 0, {
    message: "credentialSubject must not be empty",
  }),
  validFrom: z.string().min(1, "validFrom is required"),
  validUntil: z.string().optional(),
});

const batchSubmitSchema = z.object({
  schema: z.string().min(1, "schema is required"),
  signingFlow: z.enum(["interface", "delegated"]),
  credentials: z.array(credentialEntrySchema).min(1, "At least one credential is required"),
  // Interface Signing fields
  issuer: z.string().min(1).optional(),
  publicKey: z.string().min(1).optional(),
  revocationRegistryUrl: z.string().min(1).optional(),
  // Delegated Signing fields
  delegationId: z.string().min(1).optional(),
  // TODO (#176): Implement webhook callback for batch completion.
  // When provided, POST a completion notification to this URL when the batch finishes.
  // webhookUrl: z.string().url().optional(),
});

const batchSignaturesSchema = z.object({
  signatures: z
    .array(
      z.object({
        index: z.number().int().min(0),
        signature: z.string().min(1, "signature is required"),
      }),
    )
    .min(1, "At least one signature is required"),
});

const batchRevokeSchema = z
  .object({
    hashes: z
      .array(z.string().regex(/^[a-f0-9]{64}$/, "Must be a lowercase hex SHA-256 hash"))
      .optional(),
    credentials: z.array(z.record(z.unknown())).optional(),
  })
  .refine(
    (data) =>
      (data.hashes && data.hashes.length > 0) || (data.credentials && data.credentials.length > 0),
    {
      message: "Either hashes or credentials must be provided (non-empty)",
    },
  );

// ---------------------------------------------------------------------------
// Batch job types
// ---------------------------------------------------------------------------

type BatchStatus =
  | "validating"
  | "issuing"
  | "awaiting_signatures"
  | "packaging"
  | "completed"
  | "failed";

interface RowResult {
  index: number;
  status: "pending" | "issued" | "failed" | "awaiting_signature";
  credential?: VerifiableCredential;
  formats?: PackagedFormats;
  error?: string;
  // Interface Signing intermediate state
  unsignedCredential?: UnsignedCredential;
  proofConfig?: ProofConfig;
  dataToSign?: string;
}

interface BatchJob {
  jobId: string;
  status: BatchStatus;
  signingFlow: "interface" | "delegated";
  schema: string;
  total: number;
  succeeded: number;
  failed: number;
  results: RowResult[];
  // Interface Signing context
  issuer?: string;
  publicKey?: string;
  revocationRegistryUrl?: string;
  // Delegated Signing context
  delegationId?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64urlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function validateRevocationUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ValidationError("Invalid revocationRegistryUrl: must be a valid URL");
  }
  if (parsed.protocol !== "https:") {
    throw new ValidationError("revocationRegistryUrl must use HTTPS");
  }
}

function formatZodErrors(error: z.ZodError) {
  return error.issues.map((issue) => ({
    field: issue.path.join("."),
    message: issue.message,
  }));
}

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export interface BatchRouteDeps {
  config: EnvConfig;
  authOptions: AuthMiddlewareOptions;
  signingKeyProvider?: SigningKeyProvider;
  dediClient?: DeDiClient;
}

export function createBatchRoute(deps: BatchRouteDeps) {
  const { config, authOptions } = deps;
  const batch = new Hono();

  const registry = createRegistry();
  const validator = new Validator(registry);

  const jobStore = new TTLStore<BatchJob>(config.SESSION_TTL_MS, config.SESSION_SWEEP_INTERVAL_MS);

  // -----------------------------------------------------------------------
  // POST /credentials/batch — Submit batch
  // -----------------------------------------------------------------------
  batch.post(
    "/",
    authMiddleware(authOptions, "credentials:batch"),
    zValidator("json", batchSubmitSchema, (result, c) => {
      if (!result.success) {
        return c.json(
          {
            error: {
              code: "VALIDATION_ERROR",
              message: "Request validation failed",
              validationErrors: formatZodErrors(result.error),
            },
          },
          400,
        );
      }
    }),
    async (c) => {
      const body = c.req.valid("json");

      // Validate batch size
      if (body.credentials.length > config.MAX_BATCH_SIZE) {
        throw new ValidationError(
          `Batch size ${body.credentials.length} exceeds maximum of ${config.MAX_BATCH_SIZE}`,
        );
      }

      // Flow-specific validation
      if (body.signingFlow === "interface") {
        if (!body.issuer) throw new ValidationError("issuer is required for interface signing");
        if (!body.publicKey)
          throw new ValidationError("publicKey is required for interface signing");
        if (!body.revocationRegistryUrl) {
          throw new ValidationError("revocationRegistryUrl is required for interface signing");
        }
        validateRevocationUrl(body.revocationRegistryUrl);
      } else {
        if (!body.delegationId) {
          throw new ValidationError("delegationId is required for delegated signing");
        }
      }

      // Create job
      const jobId = randomUUID();
      const job: BatchJob = {
        jobId,
        status: "validating",
        signingFlow: body.signingFlow,
        schema: body.schema,
        total: body.credentials.length,
        succeeded: 0,
        failed: 0,
        results: body.credentials.map((_, i) => ({
          index: i,
          status: "pending" as const,
        })),
        issuer: body.issuer,
        publicKey: body.publicKey,
        revocationRegistryUrl: body.revocationRegistryUrl,
        delegationId: body.delegationId,
      };

      // Phase 1: Validate all rows against schema
      let hasValidationErrors = false;
      for (let i = 0; i < body.credentials.length; i++) {
        const entry = body.credentials[i];
        const result = validator.validateCredentialSubject(body.schema, entry.credentialSubject);
        if (!result.valid) {
          job.results[i] = {
            index: i,
            status: "failed",
            error: `Validation failed: ${result.errors.map((e) => `${e.field}: ${e.message}`).join("; ")}`,
          };
          job.failed++;
          hasValidationErrors = true;
        }
      }

      if (hasValidationErrors) {
        job.status = "failed";
        jobStore.set(jobId, job);
        return c.json(
          {
            jobId,
            status: job.status,
            total: job.total,
            succeeded: 0,
            failed: job.failed,
            message: "Batch validation failed. All rows must pass validation before issuance.",
          },
          202,
        );
      }

      // Phase 2: Issue credentials (flow-specific)
      if (body.signingFlow === "delegated") {
        await processDelegatedBatch(job, body, deps, validator);
      } else {
        await processInterfaceBatchPhase1(job, body, deps, validator);
      }

      jobStore.set(jobId, job);

      return c.json(
        {
          jobId,
          status: job.status,
          total: job.total,
          succeeded: job.succeeded,
          failed: job.failed,
        },
        202,
      );
    },
  );

  // -----------------------------------------------------------------------
  // POST /credentials/batch/csv — Submit batch via CSV upload
  // -----------------------------------------------------------------------
  batch.post("/csv", authMiddleware(authOptions, "credentials:batch"), async (c) => {
    const contentType = c.req.header("content-type") ?? "";
    if (!contentType.includes("multipart/form-data")) {
      throw new ValidationError("Expected multipart/form-data content type for CSV upload");
    }

    const formData = await c.req.formData();

    // Extract metadata fields from form data
    const schema = formData.get("schema");
    const signingFlow = formData.get("signingFlow");
    const file = formData.get("file");
    const validFrom = formData.get("validFrom");
    const validUntil = formData.get("validUntil") as string | null;

    // Interface Signing fields
    const issuer = formData.get("issuer") as string | null;
    const publicKey = formData.get("publicKey") as string | null;
    const revocationRegistryUrl = formData.get("revocationRegistryUrl") as string | null;

    // Delegated Signing fields
    const delegationId = formData.get("delegationId") as string | null;

    if (!schema || typeof schema !== "string") {
      throw new ValidationError("schema field is required");
    }
    if (!signingFlow || (signingFlow !== "interface" && signingFlow !== "delegated")) {
      throw new ValidationError("signingFlow must be 'interface' or 'delegated'");
    }
    if (!file || !(file instanceof File)) {
      throw new ValidationError("file field is required and must be a CSV file");
    }
    if (!validFrom || typeof validFrom !== "string") {
      throw new ValidationError("validFrom field is required");
    }

    // Flow-specific validation
    if (signingFlow === "interface") {
      if (!issuer) throw new ValidationError("issuer is required for interface signing");
      if (!publicKey) throw new ValidationError("publicKey is required for interface signing");
      if (!revocationRegistryUrl) {
        throw new ValidationError("revocationRegistryUrl is required for interface signing");
      }
      validateRevocationUrl(revocationRegistryUrl);
    } else {
      if (!delegationId) {
        throw new ValidationError("delegationId is required for delegated signing");
      }
    }

    // Parse CSV file
    const csvContent = await file.text();
    let records: Record<string, string>[];
    try {
      records = parseCsv(csvContent, {
        columns: true,
        skip_empty_lines: true,
        trim: true,
      }) as Record<string, string>[];
    } catch (err) {
      throw new ValidationError(
        `Failed to parse CSV: ${err instanceof Error ? err.message : "Invalid CSV format"}`,
      );
    }

    if (records.length === 0) {
      throw new ValidationError("CSV file contains no data rows");
    }

    if (records.length > config.MAX_BATCH_SIZE) {
      throw new ValidationError(
        `CSV contains ${records.length} rows, exceeding maximum of ${config.MAX_BATCH_SIZE}`,
      );
    }

    // Convert CSV rows to credential entries
    // Each row's columns map to credentialSubject fields
    // Special columns: validFrom, validUntil (override form-level defaults)
    const credentials: Array<{
      credentialSubject: Record<string, unknown>;
      validFrom: string;
      validUntil?: string;
    }> = [];

    for (let i = 0; i < records.length; i++) {
      const row = records[i];
      const credentialSubject: Record<string, unknown> = {};
      let rowValidFrom = validFrom;
      let rowValidUntil = validUntil ?? undefined;

      for (const [key, value] of Object.entries(row)) {
        if (key === "validFrom") {
          rowValidFrom = value;
        } else if (key === "validUntil") {
          rowValidUntil = value || undefined;
        } else {
          credentialSubject[key] = value;
        }
      }

      if (Object.keys(credentialSubject).length === 0) {
        throw new ValidationError(`CSV row ${i + 2} has no credential subject fields`);
      }

      credentials.push({
        credentialSubject,
        validFrom: rowValidFrom,
        validUntil: rowValidUntil,
      });
    }

    // Build the batch body and process using the same logic as JSON endpoint
    const body = {
      schema,
      signingFlow: signingFlow as "interface" | "delegated",
      credentials,
      issuer: issuer ?? undefined,
      publicKey: publicKey ?? undefined,
      revocationRegistryUrl: revocationRegistryUrl ?? undefined,
      delegationId: delegationId ?? undefined,
    };

    // Create job
    const jobId = randomUUID();
    const job: BatchJob = {
      jobId,
      status: "validating",
      signingFlow: body.signingFlow,
      schema: body.schema,
      total: body.credentials.length,
      succeeded: 0,
      failed: 0,
      results: body.credentials.map((_, i) => ({
        index: i,
        status: "pending" as const,
      })),
      issuer: body.issuer,
      publicKey: body.publicKey,
      revocationRegistryUrl: body.revocationRegistryUrl,
      delegationId: body.delegationId,
    };

    // Phase 1: Validate all rows against schema
    let hasValidationErrors = false;
    for (let i = 0; i < body.credentials.length; i++) {
      const entry = body.credentials[i];
      const result = validator.validateCredentialSubject(body.schema, entry.credentialSubject);
      if (!result.valid) {
        job.results[i] = {
          index: i,
          status: "failed",
          error: `Row ${i + 2}: ${result.errors.map((e) => `${e.field}: ${e.message}`).join("; ")}`,
        };
        job.failed++;
        hasValidationErrors = true;
      }
    }

    if (hasValidationErrors) {
      job.status = "failed";
      jobStore.set(jobId, job);
      return c.json(
        {
          jobId,
          status: job.status,
          total: job.total,
          succeeded: 0,
          failed: job.failed,
          message: "Batch validation failed. All rows must pass validation before issuance.",
        },
        202,
      );
    }

    // Phase 2: Issue credentials (flow-specific)
    if (body.signingFlow === "delegated") {
      await processDelegatedBatch(job, body, deps, validator);
    } else {
      await processInterfaceBatchPhase1(job, body, deps, validator);
    }

    jobStore.set(jobId, job);

    return c.json(
      {
        jobId,
        status: job.status,
        total: job.total,
        succeeded: job.succeeded,
        failed: job.failed,
      },
      202,
    );
  });

  // -----------------------------------------------------------------------
  // GET /credentials/batch/:jobId — Poll status
  // -----------------------------------------------------------------------
  batch.get("/:jobId", authMiddleware(authOptions, "credentials:batch"), async (c) => {
    const jobId = c.req.param("jobId");
    const job = jobStore.get(jobId);
    if (!job) {
      throw new SessionExpiredError("Batch job not found or expired");
    }

    return c.json({
      jobId: job.jobId,
      status: job.status,
      total: job.total,
      succeeded: job.succeeded,
      failed: job.failed,
    });
  });

  // -----------------------------------------------------------------------
  // GET /credentials/batch/:jobId/results — Per-row results
  // -----------------------------------------------------------------------
  batch.get("/:jobId/results", authMiddleware(authOptions, "credentials:batch"), async (c) => {
    const jobId = c.req.param("jobId");
    const job = jobStore.get(jobId);
    if (!job) {
      throw new SessionExpiredError("Batch job not found or expired");
    }

    const results = job.results.map((r) => {
      const row: Record<string, unknown> = {
        index: r.index,
        status: r.status,
      };

      if (r.credential) {
        row.credential = r.credential;
      }
      if (r.formats) {
        row.formats = r.formats;
      }
      if (r.error) {
        row.error = r.error;
      }
      // For interface signing in awaiting_signatures state, include signing data
      if (r.dataToSign) {
        row.dataToSign = r.dataToSign;
        row.unsignedCredential = r.unsignedCredential;
        row.proofConfig = r.proofConfig;
      }

      return row;
    });

    return c.json({
      jobId: job.jobId,
      status: job.status,
      total: job.total,
      succeeded: job.succeeded,
      failed: job.failed,
      results,
    });
  });

  // -----------------------------------------------------------------------
  // POST /credentials/batch/:jobId/signatures — Interface Signing phase 2
  // -----------------------------------------------------------------------
  batch.post(
    "/:jobId/signatures",
    authMiddleware(authOptions, "credentials:batch"),
    zValidator("json", batchSignaturesSchema, (result, c) => {
      if (!result.success) {
        return c.json(
          {
            error: {
              code: "VALIDATION_ERROR",
              message: "Request validation failed",
              validationErrors: formatZodErrors(result.error),
            },
          },
          400,
        );
      }
    }),
    async (c) => {
      const jobId = c.req.param("jobId");
      const job = jobStore.get(jobId);
      if (!job) {
        throw new SessionExpiredError("Batch job not found or expired");
      }

      if (job.signingFlow !== "interface") {
        throw new ValidationError("Signatures endpoint is only for interface signing batches");
      }
      if (job.status !== "awaiting_signatures") {
        throw new ValidationError(
          `Cannot submit signatures: batch is in '${job.status}' state, expected 'awaiting_signatures'`,
        );
      }

      const body = c.req.valid("json");

      // Validate all signature indices are within range and refer to pending rows
      for (const sig of body.signatures) {
        if (sig.index >= job.total || sig.index < 0) {
          throw new ValidationError(`Invalid index: ${sig.index} (batch has ${job.total} rows)`);
        }
        if (job.results[sig.index].status !== "awaiting_signature") {
          throw new ValidationError(
            `Row ${sig.index} is in '${job.results[sig.index].status}' state, not awaiting signature`,
          );
        }
      }

      job.status = "packaging";

      for (const sig of body.signatures) {
        const row = job.results[sig.index];
        try {
          const signatureBytes = base64urlDecode(sig.signature);
          if (signatureBytes.length !== 64) {
            throw new ValidationError(
              `Invalid signature for row ${sig.index}: expected 64 bytes (P-256 ECDSA r||s format)`,
            );
          }

          const credential = completeProof(
            row.unsignedCredential!,
            row.proofConfig!,
            signatureBytes,
          );

          row.credential = credential;
          row.status = "issued";
          job.succeeded++;

          // Generate QR + PDF output formats
          row.formats = await packageFormats(credential as unknown as Record<string, unknown>);

          // Clear intermediate signing state
          row.unsignedCredential = undefined;
          row.proofConfig = undefined;
          row.dataToSign = undefined;
        } catch (err) {
          row.status = "failed";
          row.error = err instanceof Error ? err.message : "Signature packaging failed";
          job.failed++;
        }
      }

      // Check if all rows are processed
      const allProcessed = job.results.every((r) => r.status === "issued" || r.status === "failed");
      if (allProcessed) {
        job.status = "completed";
      }

      jobStore.set(jobId, job);

      return c.json({
        jobId: job.jobId,
        status: job.status,
        total: job.total,
        succeeded: job.succeeded,
        failed: job.failed,
      });
    },
  );

  return { batch, jobStore };
}

// ---------------------------------------------------------------------------
// Batch revocation route (mounted separately at /credentials/revoke/batch)
// ---------------------------------------------------------------------------

export function createBatchRevokeRoute(dediClient: DeDiClient) {
  const route = new Hono();

  route.post(
    "/credentials/revoke/batch",
    zValidator("json", batchRevokeSchema, (result, c) => {
      if (!result.success) {
        return c.json(
          {
            error: {
              code: "VALIDATION_ERROR",
              message: "Request validation failed",
              validationErrors: formatZodErrors(result.error),
            },
          },
          400,
        );
      }
    }),
    async (c) => {
      const body = c.req.valid("json");

      // Collect all hashes to revoke
      const hashEntries: Array<{ hash: string; source: "provided" | "computed"; index: number }> =
        [];

      if (body.hashes) {
        for (let i = 0; i < body.hashes.length; i++) {
          hashEntries.push({ hash: body.hashes[i], source: "provided", index: i });
        }
      }

      if (body.credentials) {
        for (let i = 0; i < body.credentials.length; i++) {
          const hash = computeRevocationHash(body.credentials[i]);
          hashEntries.push({ hash, source: "computed", index: i });
        }
      }

      // Publish all hashes to DeDi
      const results: Array<{ hash: string; status: "revoked" | "failed"; error?: string }> = [];

      for (const entry of hashEntries) {
        try {
          await dediClient.publishRevocationHash(entry.hash);
          results.push({ hash: entry.hash, status: "revoked" });
        } catch (err) {
          results.push({
            hash: entry.hash,
            status: "failed",
            error: err instanceof Error ? err.message : "Revocation failed",
          });
        }
      }

      const succeeded = results.filter((r) => r.status === "revoked").length;
      const failed = results.filter((r) => r.status === "failed").length;

      return c.json({
        total: results.length,
        succeeded,
        failed,
        results,
      });
    },
  );

  return route;
}

// ---------------------------------------------------------------------------
// Batch processing helpers
// ---------------------------------------------------------------------------

async function processDelegatedBatch(
  job: BatchJob,
  body: z.infer<typeof batchSubmitSchema>,
  deps: BatchRouteDeps,
  _validator: Validator,
): Promise<void> {
  if (!deps.signingKeyProvider || !deps.dediClient) {
    throw new ValidationError("Delegated signing is not configured on this server");
  }

  const { signingKeyProvider, dediClient, config } = deps;
  const dediBaseUrl = config.DEDI_API_URL ?? "https://dedi.example";

  // Resolve and validate delegation
  const delegation = await resolveDelegation(dediClient, {
    delegationId: body.delegationId!,
  });

  const validationResult = await validateDelegationCertificate(delegation, {
    credentialType: body.schema,
  });

  if (!validationResult.valid) {
    if (validationResult.status === "expired") {
      throw new AuthorizationError(
        `Delegation certificate has expired: ${validationResult.errors.join("; ")}`,
      );
    }
    if (validationResult.status === "revoked") {
      throw new AuthorizationError(
        `Delegation certificate has been revoked: ${validationResult.errors.join("; ")}`,
      );
    }
    throw new AuthorizationError(
      `Delegation validation failed: ${validationResult.errors.join("; ")}`,
    );
  }

  // Check revocation status
  const revocationHash = computeRevocationHash({ delegationId: body.delegationId });
  const revocationRecord = await dediClient.queryRevocationHash(revocationHash);
  if (revocationRecord.revoked) {
    throw new AuthorizationError("Delegation has been revoked");
  }

  // Validate delegatee matches signing key
  const activeKey = signingKeyProvider.getActiveKey();
  if (delegation.delegatee.id !== activeKey.id) {
    throw new AuthorizationError("Delegation does not authorize the current signing key");
  }

  job.status = "issuing";

  // Derive issuer from delegation
  const issuer = delegation.delegator.name
    ? { id: delegation.delegator.id, name: delegation.delegator.name }
    : delegation.delegator.id;

  // Issue each credential
  for (let i = 0; i < body.credentials.length; i++) {
    const entry = body.credentials[i];
    try {
      const builder = new CredentialBuilder()
        .setIssuer(issuer)
        .setCredentialSubject(entry.credentialSubject)
        .setValidFrom(entry.validFrom)
        .setCredentialStatus({
          id: `${dediBaseUrl}/revocations/${encodeURIComponent(delegation.delegator.id)}/registry`,
          type: "DeDiRevocationListStatusV1",
          statusPurpose: "revocation",
        });

      if (entry.validUntil) {
        builder.setValidUntil(entry.validUntil);
      }

      const unsignedCredential = builder.build();

      const signedCredential = await signCredential(unsignedCredential, activeKey, {
        verificationMethod: activeKey.id,
        proofPurpose: "assertionMethod",
      });

      const credentialWithDelegation = embedDelegation(signedCredential, delegation);

      // Generate QR + PDF output formats
      const formats = await packageFormats(
        credentialWithDelegation as unknown as Record<string, unknown>,
      );

      job.results[i] = {
        index: i,
        status: "issued",
        credential: credentialWithDelegation,
        formats,
      };
      job.succeeded++;
    } catch (err) {
      job.results[i] = {
        index: i,
        status: "failed",
        error: err instanceof Error ? err.message : "Issuance failed",
      };
      job.failed++;
    }
  }

  job.status = "completed";
}

async function processInterfaceBatchPhase1(
  job: BatchJob,
  body: z.infer<typeof batchSubmitSchema>,
  _deps: BatchRouteDeps,
  _validator: Validator,
): Promise<void> {
  // Build unsigned credentials and prepare proofs for all rows
  for (let i = 0; i < body.credentials.length; i++) {
    const entry = body.credentials[i];
    try {
      const builder = new CredentialBuilder()
        .setIssuer(body.issuer!)
        .setCredentialSubject(entry.credentialSubject)
        .setValidFrom(entry.validFrom)
        .setCredentialStatus({
          id: body.revocationRegistryUrl!,
          type: "DeDiRevocationListStatusV1",
          statusPurpose: "revocation",
        });

      if (entry.validUntil) {
        builder.setValidUntil(entry.validUntil);
      }

      const unsignedCredential = builder.build();

      const verificationMethod = `${body.issuer}#${body.publicKey}`;
      const prepared = await prepareProof(unsignedCredential, {
        verificationMethod,
        proofPurpose: "assertionMethod",
      });

      job.results[i] = {
        index: i,
        status: "awaiting_signature",
        unsignedCredential,
        proofConfig: prepared.proofConfig,
        dataToSign: base64urlEncode(prepared.dataToSign),
      };
    } catch (err) {
      job.results[i] = {
        index: i,
        status: "failed",
        error: err instanceof Error ? err.message : "Proof preparation failed",
      };
      job.failed++;
    }
  }

  // If any rows failed during proof preparation, mark the job as failed
  if (job.failed > 0) {
    job.status = "failed";
  } else {
    job.status = "awaiting_signatures";
  }
}
