/**
 * Critical-path span content tests (#581 / #446 Tier 3 #10).
 *
 * Exercises the OTel instrumentation surface via an in-memory exporter:
 *
 *   - `http.server` spans named after the route pattern (e.g.
 *     `POST /credentials/issue`)
 *   - `signer.sign` spans with algorithm / kind / fingerprint
 *   - `batch.run` + per-row `batch.row.process` spans nested under it
 *   - `verify.credential` / `verify.did_resolve` / `verify.schema_validate`
 *
 * Each test uses a freshly-created InMemorySpanExporter so spans from
 * previous test cases don't leak. The exporter is wired up via
 * `setInMemoryExporter` before exercising the route under test.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { InMemorySpanExporter, type ReadableSpan } from "@opentelemetry/sdk-trace-base";
import type { Hono } from "hono";

import { createTestApp, generateTestKey, type TestKeyPair } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import { wrapSignerWithTracing } from "../observability/signer-span.js";
import { setInMemoryExporter, resetTracingForTesting } from "../tracing.js";
import { createBatchEngine } from "../batch/batch-engine.js";
import type { ParsedRow } from "../batch/csv-parser.js";

let exporter: InMemorySpanExporter;

async function setupExporter() {
  exporter = new InMemorySpanExporter();
  await setInMemoryExporter(exporter);
}

async function teardownExporter() {
  await resetTracingForTesting();
  exporter?.reset();
}

function spanNames(spans: ReadableSpan[]): string[] {
  return spans.map((s) => s.name);
}

describe("HTTP server spans", () => {
  let app: Hono;
  let key: TestKeyPair;

  beforeEach(async () => {
    await setupExporter();
    key = generateTestKey();
    app = createTestApp({ devModeNoAuth: true });
    setActiveSigner(wrapSignerWithTracing(key.signer, "software"));
  });

  afterEach(async () => {
    setActiveSigner(null);
    await teardownExporter();
  });

  it("creates an http.server span named after the route pattern", async () => {
    const res = await app.request("/health");
    expect(res.status).toBe(200);

    const spans = exporter.getFinishedSpans();
    // `/health` is mounted at both "/" and "/v1" — under "/" the
    // pattern is just "/health", so the span name is "GET /health".
    const httpSpan = spans.find((s) => s.name === "GET /health");
    expect(httpSpan).toBeDefined();
    expect(httpSpan!.kind).toBeDefined();
    expect(httpSpan!.attributes["http.request.method"]).toBe("GET");
    expect(httpSpan!.attributes["http.response.status_code"]).toBe(200);
  });

  it("normalises UUIDs in the path when no route pattern matches", async () => {
    const res = await app.request("/credentials/batch/00000000-0000-0000-0000-000000000000");
    // The route exists; if jobId not found, returns 404. Span name
    // should be the registered pattern, NOT the raw UUID.
    expect([200, 404]).toContain(res.status);
    const spans = exporter.getFinishedSpans();
    const httpSpan = spans.find((s) => s.name.startsWith("GET /credentials/batch/"));
    expect(httpSpan).toBeDefined();
    // The pattern is `:jobId` — the raw UUID must not appear in any
    // span name.
    expect(httpSpan!.name).not.toContain("00000000");
  });
});

describe("signer.sign spans", () => {
  let key: TestKeyPair;

  beforeEach(async () => {
    await setupExporter();
    key = generateTestKey();
  });

  afterEach(async () => {
    await teardownExporter();
  });

  it("emits a signer.sign span with algorithm + kind + fingerprint", async () => {
    const traced = wrapSignerWithTracing(key.signer, "software");
    const sig = await traced.sign(new TextEncoder().encode("hello"));
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.byteLength).toBeGreaterThan(0);

    const spans = exporter.getFinishedSpans();
    const span = spans.find((s) => s.name === "signer.sign");
    expect(span).toBeDefined();
    expect(span!.attributes["signer.algorithm"]).toBe("P-256");
    expect(span!.attributes["signer.kind"]).toBe("software");
    expect(span!.attributes["signer.fingerprint"]).toBe(key.signer.metadata.fingerprint);
    expect(span!.attributes["signer.input_bytes"]).toBe(5);
    expect(span!.attributes["signer.signature_bytes"]).toBeGreaterThan(0);
  });

  it("never records the data-to-sign content or signature bytes themselves", async () => {
    const traced = wrapSignerWithTracing(key.signer, "software");
    const sensitive = new TextEncoder().encode("secret-credential-payload");
    await traced.sign(sensitive);

    const spans = exporter.getFinishedSpans();
    const span = spans.find((s) => s.name === "signer.sign");
    expect(span).toBeDefined();
    // SECURITY: every attribute value must be primitive metadata —
    // never the data-to-sign content, never the signature bytes.
    for (const [k, v] of Object.entries(span!.attributes)) {
      if (typeof v === "string") {
        expect(v.includes("secret-credential-payload")).toBe(false);
        expect(k.includes("data") || k.includes("signature")).toBe(false);
      }
    }
  });

  it("emits cloud-hsm-aws kind when wrapped as such", async () => {
    const traced = wrapSignerWithTracing(key.signer, "cloud-hsm-aws");
    await traced.sign(new Uint8Array([1, 2, 3]));
    const span = exporter.getFinishedSpans().find((s) => s.name === "signer.sign");
    expect(span!.attributes["signer.kind"]).toBe("cloud-hsm-aws");
  });
});

describe("batch.row.process spans", () => {
  let key: TestKeyPair;

  beforeEach(async () => {
    await setupExporter();
    key = generateTestKey();
  });

  afterEach(async () => {
    await teardownExporter();
  });

  it("emits one batch.row.process span per row, nested under batch.run", async () => {
    const traced = wrapSignerWithTracing(key.signer, "software");
    const rows: ParsedRow[] = [
      {
        rowIndex: 0,
        rawValues: { givenName: "Alice" },
        mappedSubject: { givenName: "Alice" },
        valid: true,
        errors: [],
      },
      {
        rowIndex: 1,
        rawValues: { givenName: "Bob" },
        mappedSubject: { givenName: "Bob" },
        valid: true,
        errors: [],
      },
    ];

    // Stub validator — generally createBatchEngine reaches for
    // `getValidator()`. For this test we accept any subject; install
    // a permissive validator-singleton via the test helper's path.
    // The simplest route is to use a validator-passing schema that
    // accepts all subjects. We install a tiny one inline.
    const { setValidator } = await import("../validator-singleton.js");
    const stubValidator = {
      validateOrThrow() {
        /* no-op */
      },
      validate() {
        return { valid: true, errors: [] };
      },
      validateInline() {
        return { valid: true, errors: [] };
      },
      validateInlineOrThrow() {
        /* no-op */
      },
    };
    setValidator(stubValidator as unknown as Parameters<typeof setValidator>[0]);

    const engine = createBatchEngine(
      traced,
      rows,
      {
        schemaId: "test/v1",
        issuerDid: traced.id.split("#")[0],
        validFrom: new Date().toISOString(),
        proofFormat: "vc-jwt",
      },
      { jobId: "test-job-uuid", concurrency: 2 },
    );

    const finalProgress = await engine.start();
    expect(finalProgress.successCount).toBe(2);

    const spans = exporter.getFinishedSpans();
    const rowSpans = spans.filter((s) => s.name === "batch.row.process");
    expect(rowSpans.length).toBe(2);
    for (const span of rowSpans) {
      expect(span.attributes["batch.proof_format"]).toBe("vc-jwt");
      expect(span.attributes["batch.job_id"]).toBe("test-job-uuid");
      expect(span.attributes["batch.row_status"]).toBe("success");
      expect(typeof span.attributes["batch.row_index"]).toBe("number");
    }

    const batchSpan = spans.find((s) => s.name === "batch.run");
    expect(batchSpan).toBeDefined();
    expect(batchSpan!.attributes["batch.job_id"]).toBe("test-job-uuid");
    expect(batchSpan!.attributes["batch.total_rows"]).toBe(2);

    // Per-row spans should be children of the batch.run span.
    for (const rowSpan of rowSpans) {
      expect(rowSpan.parentSpanId).toBe(batchSpan!.spanContext().spanId);
    }
  });
});

describe("DeDi adapter spans", () => {
  beforeEach(async () => {
    await setupExporter();
  });

  afterEach(async () => {
    await teardownExporter();
  });

  it("wraps lookup/publish/update with named spans + host attribute (no path)", async () => {
    const { wrapDeDiClientWithTracing } = await import("../observability/dedi-span.js");
    // Build a minimal stub matching the DeDiClient surface for the
    // wrapped methods. We only care that the wrapper produces spans
    // with the correct names + attributes; the underlying client is
    // a no-op.
    const stub = {
      apiClient: {} as never,
      logger: {
        info: () => undefined,
        warn: () => undefined,
        error: () => undefined,
        debug: () => undefined,
      },
      async publishRevocationHash() {
        return { revoked: true, revokedAt: new Date().toISOString() } as const;
      },
      async queryRevocationHash() {
        return { revoked: false } as const;
      },
      async publishDID() {
        return { published: true, recordName: "x", namespace: "ns" };
      },
      async resolveDID() {
        return { did: "did:web:x", keyStatus: "current" as const };
      },
      async markDIDRotated() {
        /* no-op */
      },
      async publishSchema() {
        return { published: true, recordName: "x", namespace: "ns" };
      },
      async resolveSchema() {
        return {
          schemaId: "x",
          version: "1.0.0",
          schema: {},
          checksum: "x",
          publishedAt: new Date().toISOString(),
        };
      },
      async publishContext() {
        return { published: true, recordName: "x", namespace: "ns" };
      },
      async resolveContext() {
        return {
          schemaId: "x",
          version: "1.0.0",
          context: {},
          publishedAt: new Date().toISOString(),
        };
      },
      async ensureRegistries() {
        /* no-op */
      },
    };
    const wrapped = wrapDeDiClientWithTracing(
      stub as never,
      "https://dedi.example.org/some/path?token=secret",
    );

    await wrapped.queryRevocationHash("abc", "ns");
    await wrapped.publishDID("did:web:x", {}, "ns");
    await wrapped.markDIDRotated("did:web:x", "ns");

    const spans = exporter.getFinishedSpans();
    const lookup = spans.find((s) => s.name === "dedi.lookup_record");
    const publish = spans.find((s) => s.name === "dedi.publish_record");
    const update = spans.find((s) => s.name === "dedi.update_record");
    expect(lookup).toBeDefined();
    expect(publish).toBeDefined();
    expect(update).toBeDefined();

    // Host only — never path, never token.
    expect(lookup!.attributes["dedi.host"]).toBe("dedi.example.org");
    for (const span of [lookup!, publish!, update!]) {
      for (const v of Object.values(span.attributes)) {
        if (typeof v === "string") {
          expect(v.includes("token=secret")).toBe(false);
          expect(v.includes("/some/path")).toBe(false);
        }
      }
    }
  });
});

describe("verify spans", () => {
  let app: Hono;
  let key: TestKeyPair;

  beforeEach(async () => {
    await setupExporter();
    key = generateTestKey();
    app = createTestApp({ devModeNoAuth: true });
    setActiveSigner(wrapSignerWithTracing(key.signer, "software"));
  });

  afterEach(async () => {
    setActiveSigner(null);
    await teardownExporter();
  });

  it("emits verify.schema_validate + verify.did_resolve + verify.credential on a verify roundtrip", async () => {
    // Issue a vc-jwt against the registry-resident `functional-identity/v1`
    // schema (loaded by createTestApp). Then verify it and inspect the spans.
    const issueRes = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        schemaId: "functional-identity/v1",
        credentialSubject: {
          name: "Jane Doe",
          role: "Medical Practitioner",
          validFrom: "2025-06-15T00:00:00Z",
          affiliation: { name: "Acme Medical Council" },
        },
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat: "vc-jwt",
      }),
    });
    expect(issueRes.status).toBe(200);
    // For vc-jwt the route returns the credential as a JSON object
    // with `proof.jwt`. The verify endpoint accepts a compact JWT
    // string directly; pull it out of `proof.jwt` so the verifier
    // routes through the vc-jwt path (where `verify.did_resolve` is
    // reached via `resolveIssuerKey`).
    const issued = (await issueRes.json()) as {
      credential: { proof?: { jwt?: string } } | string;
    };

    // schema_validate is recorded on the issue path.
    const issueSpans = exporter.getFinishedSpans();
    expect(spanNames(issueSpans)).toContain("verify.schema_validate");
    const sv = issueSpans.find((s) => s.name === "verify.schema_validate")!;
    expect(sv.attributes["verify.schema_id"]).toBe("functional-identity/v1");

    exporter.reset();

    const credentialStr =
      typeof issued.credential === "string"
        ? issued.credential
        : (issued.credential.proof?.jwt ?? JSON.stringify(issued.credential));
    const verRes = await app.request("/credentials/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ credential: credentialStr }),
    });
    expect(verRes.status).toBe(200);
    const verifyNames = spanNames(exporter.getFinishedSpans());
    expect(verifyNames).toContain("verify.credential");
    expect(verifyNames).toContain("verify.did_resolve");

    const vc = exporter.getFinishedSpans().find((s) => s.name === "verify.credential")!;
    expect(["VALID", "INVALID", "UNRESOLVABLE", "REVOKED", "EXPIRED", "CONTEXT_MISSING"]).toContain(
      vc.attributes["verify.code"] as string,
    );

    // did_resolve spans should be children of verify.credential (or its
    // ancestors). Verify the parent chain is set up correctly — if the
    // active-span context broke, the resolver would emit a root span.
    const didSpan = exporter.getFinishedSpans().find((s) => s.name === "verify.did_resolve")!;
    expect(didSpan.parentSpanId).toBeDefined();
  });
});
