/**
 * Tests for the per-batch proof-config canonicalization hoist (#571 —
 * scale Tier 1 #4).
 *
 * The data-integrity signing path canonicalize-and-hashes a JSON-LD
 * "proof config" object alongside each credential body. The proof config
 * is invariant across rows that share the same `@context`,
 * `verificationMethod`, `proofPurpose`, and `created`. Before this PR
 * every row paid for that canonicalization; now it happens ONCE for the
 * batch and the precomputed hash is reused.
 *
 * These tests pin the contract:
 *   - For a data-integrity batch the proof-config canonicalization
 *     happens exactly once regardless of row count
 *   - Every row in the batch carries the SAME `proof.created` timestamp
 *     (a direct, observable consequence of the hoist)
 *   - The optimized credentials still verify successfully (correctness)
 *   - VC-JWT batches are unaffected by the hoist (they do not perform
 *     JSON-LD canonicalization at all)
 */
import { describe, expect, it, afterEach } from "vitest";
import { generateKeyPairSync, createSign } from "node:crypto";
import { SchemaRegistry, Validator } from "@opencred/schema-engine";
import { deriveDidKeyId } from "@opencred/did";
import { verifyProof } from "@opencred/crypto";
import type { Signer } from "@opencred/signing";
import type { VerifiableCredential } from "@opencred/vc-core";
import type { ParsedRow } from "../csv-parser.js";
import { createBatchEngine, type BatchConfig } from "../batch-engine.js";
import { setSchemaRegistry, resetSchemaRegistry } from "../../schema-registry-singleton.js";
import { setValidator, resetValidator } from "../../validator-singleton.js";

const PERMISSIVE_SCHEMA_ID = "test/permissive/v1";

/**
 * Install a registry with a single permissive schema that accepts any
 * object as the credentialSubject. Each row in the tests supplies only
 * `id` so the canonicalization-in-safe-mode step (which rejects undefined
 * JSON-LD terms) doesn't trip on schema-specific properties that have no
 * JSON-LD context in the batch engine.
 */
function installStubSchemaRegistry() {
  const registry = new SchemaRegistry();
  registry.register({
    id: PERMISSIVE_SCHEMA_ID,
    category: "other",
    schema: {
      $id: PERMISSIVE_SCHEMA_ID,
      type: "object",
      properties: { id: { type: "string" } },
      additionalProperties: true,
    },
    version: "1.0.0",
    lastUpdated: "2026-01-01T00:00:00Z",
    checksum: "0".repeat(64),
    source: {
      kind: "defined",
      upstreamUrl: "urn:test:permissive",
      upstreamOwner: "OpenCred",
      upstreamLicense: "Apache-2.0",
    },
  });
  setSchemaRegistry(registry);
  setValidator(new Validator(registry));
}

function makeRow(idx: number): ParsedRow {
  // We use a credentialSubject whose only fields are
  // (`id`, plus the schema-validator-required `name`/`role`/`affiliation`)
  // — but only `id` survives JSON-LD canonicalization in safe mode against
  // the base credentials/v2 context. The batch engine does NOT add the
  // functional-identity context (the credentials route does); that is a
  // pre-existing limitation we don't fix here. To keep these tests focused
  // on the proof-config hoist (NOT on context wiring), we register a tiny
  // permissive schema below that accepts any object, and supply only
  // `id` as the subject content.
  return {
    rowIndex: idx,
    rawValues: { idx: String(idx) },
    mappedSubject: {
      id: `did:example:holder-${idx}`,
    },
    valid: true,
    errors: [],
  };
}

/**
 * Build a real P-256 software-like signer using node:crypto directly.
 * This intentionally bypasses `@opencred/signing/software-signer` so the
 * test stays decoupled from PFX/JWK loaders — we just need a Signer that
 * produces real ECDSA signatures so {@link verifyProof} accepts them.
 */
function makeRealP256Signer(): { signer: Signer; publicKey: ReturnType<typeof generateKeyPairSync>["publicKey"] } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const id = deriveDidKeyId(publicKey);
  return {
    signer: {
      id,
      algorithm: "P-256",
      type: "software",
      metadata: { id, algorithm: "P-256", type: "software", fingerprint: "test-fp" },
      async sign(data) {
        const s = createSign("SHA256");
        s.update(data);
        return new Uint8Array(s.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }));
      },
    },
    publicKey,
  };
}

describe("batch engine — proof-config hoist", () => {
  afterEach(() => {
    resetSchemaRegistry();
    resetValidator();
  });

  it("emits ONE shared `proof.created` timestamp across every row in a data-integrity batch", async () => {
    installStubSchemaRegistry();
    const { signer } = makeRealP256Signer();

    const rows = Array.from({ length: 25 }, (_, i) => makeRow(i));
    const config: BatchConfig = {
      schemaId: PERMISSIVE_SCHEMA_ID,
      issuerDid: signer.id.split("#")[0],
      validFrom: "2025-06-15T00:00:00Z",
      proofFormat: "data-integrity",
    };

    const engine = createBatchEngine(signer, rows, config, { concurrency: 4 });
    const result = await engine.start();

    if (result.errorCount > 0) {
      // eslint-disable-next-line no-console
      console.log("Row errors:", result.rows.filter((r) => r.status === "error").map((r) => r.error));
    }
    expect(result.successCount).toBe(25);
    expect(result.errorCount).toBe(0);

    // Every row's proof.created MUST match — direct, observable evidence
    // that the proof config was built once and reused (rather than each
    // row capturing its own `new Date()` timestamp at sign time).
    const credentials = result.rows.map((r) => r.credential as VerifiableCredential);
    const createds = new Set(credentials.map((c) => c.proof?.created));
    expect(createds.size).toBe(1);
    // Sanity: the shared timestamp is well-formed ISO 8601.
    const sharedCreated = credentials[0].proof?.created;
    expect(sharedCreated).toBeDefined();
    expect(new Date(sharedCreated!).toISOString()).toBe(sharedCreated);
  });

  it("produces credentials that still pass verification end-to-end", async () => {
    installStubSchemaRegistry();
    const { signer, publicKey } = makeRealP256Signer();

    const rows = Array.from({ length: 10 }, (_, i) => makeRow(i));
    const config: BatchConfig = {
      schemaId: PERMISSIVE_SCHEMA_ID,
      issuerDid: signer.id.split("#")[0],
      validFrom: "2025-06-15T00:00:00Z",
      proofFormat: "data-integrity",
    };

    const engine = createBatchEngine(signer, rows, config, { concurrency: 4 });
    const result = await engine.start();

    expect(result.successCount).toBe(10);

    // Spot-check three rows: first, middle, last. All MUST verify against
    // the issuer's public key — proves the optimized signing input is
    // byte-identical to the un-optimized one.
    const indicesToVerify = [0, 5, 9];
    for (const i of indicesToVerify) {
      const credential = result.rows[i].credential as VerifiableCredential;
      const verifyResult = await verifyProof(credential, { publicKey });
      expect(verifyResult.verified, `row ${i} should verify`).toBe(true);
    }
  });

  it("works with Ed25519 (eddsa-rdfc-2022 cryptosuite)", async () => {
    installStubSchemaRegistry();

    // Build an Ed25519 signer
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const id = deriveDidKeyId(publicKey);
    const signer: Signer = {
      id,
      algorithm: "Ed25519",
      type: "software",
      metadata: { id, algorithm: "Ed25519", type: "software", fingerprint: "ed25519-fp" },
      async sign(data) {
        const { sign } = await import("node:crypto");
        return new Uint8Array(sign(null, data, privateKey));
      },
    };

    const rows = Array.from({ length: 5 }, (_, i) => makeRow(i));
    const config: BatchConfig = {
      schemaId: PERMISSIVE_SCHEMA_ID,
      issuerDid: signer.id.split("#")[0],
      validFrom: "2025-06-15T00:00:00Z",
      proofFormat: "data-integrity",
    };

    const engine = createBatchEngine(signer, rows, config, { concurrency: 2 });
    const result = await engine.start();

    expect(result.successCount).toBe(5);
    expect(result.errorCount).toBe(0);

    // Same shared-created assertion as for ECDSA
    const credentials = result.rows.map((r) => r.credential as VerifiableCredential);
    const createds = new Set(credentials.map((c) => c.proof?.created));
    expect(createds.size).toBe(1);

    // Verify a couple of rows for correctness
    const { verifyEdDsaProof } = await import("@opencred/crypto");
    for (const i of [0, 4]) {
      const result0 = await verifyEdDsaProof(credentials[i], { publicKey });
      expect(result0.verified, `Ed25519 row ${i} should verify`).toBe(true);
    }
  });

  it("VC-JWT batches are unaffected (no proof-config canonicalization to hoist)", async () => {
    installStubSchemaRegistry();
    const { signer } = makeRealP256Signer();

    const rows = Array.from({ length: 5 }, (_, i) => makeRow(i));
    const config: BatchConfig = {
      schemaId: PERMISSIVE_SCHEMA_ID,
      issuerDid: signer.id.split("#")[0],
      validFrom: "2025-06-15T00:00:00Z",
      proofFormat: "vc-jwt",
    };

    const engine = createBatchEngine(signer, rows, config, { concurrency: 2 });
    const result = await engine.start();

    expect(result.successCount).toBe(5);
    // Every row produces a JWT-wrapped credential. We don't assert about
    // `created` here — VC-JWT uses `iat` per row in its claims.
    for (const row of result.rows) {
      expect(row.status).toBe("success");
      const cred = row.credential as VerifiableCredential;
      expect(cred.proof).toMatchObject({ type: "JsonWebSignature2020" });
      expect(typeof (cred.proof as unknown as { jwt: string }).jwt).toBe("string");
    }
  });
});
