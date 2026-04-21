#!/usr/bin/env npx tsx
/**
 * Scale / load testing script for the OpenCred server.
 *
 * Uses `autocannon` (Node.js HTTP benchmarking tool) to run configurable
 * scenarios against a running server instance — either inside Docker or a
 * local `node dist/index.js` / `tsx src/index.ts` process.
 *
 * Usage:
 *   # Against a local server on port 3100 with auth disabled:
 *   OPENCRED_DEV_MODE_NO_AUTH=true npx tsx scripts/scale-test.ts
 *
 *   # Against a Docker container on port 8080 with an API key:
 *   SCALE_TEST_BASE_URL=http://localhost:8080 \
 *   SCALE_TEST_API_KEY=my-api-key \
 *   npx tsx scripts/scale-test.ts
 *
 *   # Run only specific scenarios:
 *   npx tsx scripts/scale-test.ts --scenarios health,issue
 *
 *   # Adjust duration and concurrency:
 *   npx tsx scripts/scale-test.ts --duration 30 --connections 50
 *
 * Environment variables:
 *   SCALE_TEST_BASE_URL   — server origin (default: http://localhost:3100)
 *   SCALE_TEST_API_KEY    — bearer token (omit for dev-mode servers)
 *   SCALE_TEST_DURATION   — seconds per scenario (default: 10)
 *   SCALE_TEST_CONNECTIONS — concurrent connections (default: 10)
 *
 * SECURITY: This script generates an ephemeral test key in /tmp for the
 * server's OPENCRED_KEY_PATH. It is deleted on exit. No real signing keys
 * are used.
 */

import autocannon from "autocannon";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

interface ScaleTestConfig {
  baseUrl: string;
  apiKey?: string;
  duration: number;
  connections: number;
  scenarios: string[];
}

function parseArgs(): ScaleTestConfig {
  const args = process.argv.slice(2);
  const config: ScaleTestConfig = {
    baseUrl: process.env.SCALE_TEST_BASE_URL ?? "http://localhost:3100",
    apiKey: process.env.SCALE_TEST_API_KEY,
    duration: Number(process.env.SCALE_TEST_DURATION ?? "10"),
    connections: Number(process.env.SCALE_TEST_CONNECTIONS ?? "10"),
    scenarios: ["health", "issue", "verify", "mixed", "batch"],
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--scenarios":
        config.scenarios = (args[++i] ?? "").split(",").map((s) => s.trim());
        break;
      case "--duration":
        config.duration = Number(args[++i]);
        break;
      case "--connections":
        config.connections = Number(args[++i]);
        break;
      case "--base-url":
        config.baseUrl = args[++i] ?? config.baseUrl;
        break;
      case "--api-key":
        config.apiKey = args[++i];
        break;
      case "--help":
        printHelp();
        process.exit(0);
        break;
    }
  }

  return config;
}

function printHelp(): void {
  console.log(`
OpenCred Scale Test

Usage: npx tsx scripts/scale-test.ts [options]

Options:
  --scenarios <list>   Comma-separated scenario names (default: health,issue,verify,mixed,batch)
  --duration <sec>     Seconds per scenario (default: 10)
  --connections <n>    Concurrent connections (default: 10)
  --base-url <url>     Server URL (default: http://localhost:3100)
  --api-key <key>      Bearer token for authenticated servers
  --help               Show this help

Scenarios:
  health   — GET /health (baseline throughput)
  issue    — POST /credentials/issue (single credential)
  verify   — POST /credentials/verify (single credential)
  mixed    — 70% verify, 20% issue, 10% health (realistic workload)
  batch    — POST /credentials/batch with varying row counts

Environment:
  SCALE_TEST_BASE_URL     — same as --base-url
  SCALE_TEST_API_KEY      — same as --api-key
  SCALE_TEST_DURATION     — same as --duration
  SCALE_TEST_CONNECTIONS  — same as --connections
`);
}

// ---------------------------------------------------------------------------
// Test payloads
// ---------------------------------------------------------------------------

const FUNCTIONAL_IDENTITY_SUBJECT = {
  name: "Jane Doe",
  role: "Medical Practitioner",
  validFrom: "2025-06-15T00:00:00Z",
  affiliation: { name: "Acme Medical Council" },
};

// issuerDid is populated at runtime from the server's /keys endpoint so that
// verify and mixed scenarios can resolve the DID.  The placeholder below is
// overwritten in main() before any scenario runs.
let ISSUE_PAYLOAD = {
  schemaId: "functional-identity/v1",
  issuerDid: "", // set by discoverIssuerDid()
  credentialSubject: FUNCTIONAL_IDENTITY_SUBJECT,
  validFrom: "2025-06-15T00:00:00Z",
  proofFormat: "vc-jwt",
};

function makeHeaders(apiKey?: string): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }
  return headers;
}

function makeBatchCsv(rowCount: number): string {
  const header = "name,role,validFrom";
  const rows: string[] = [header];
  for (let i = 0; i < rowCount; i++) {
    rows.push(`Person ${i},Medical Practitioner,2025-06-15T00:00:00Z`);
  }
  return rows.join("\n");
}

// ---------------------------------------------------------------------------
// Scenario runners
// ---------------------------------------------------------------------------

interface ScenarioResult {
  name: string;
  requestsPerSec: number;
  latencyP50: number;
  latencyP95: number;
  latencyP99: number;
  latencyAvg: number;
  totalRequests: number;
  errors: number;
  timeouts: number;
  non2xx: number;
  duration: number;
  connections: number;
}

function formatResult(result: autocannon.Result, name: string): ScenarioResult {
  return {
    name,
    requestsPerSec: result.requests.average,
    latencyP50: result.latency.p50,
    latencyP95: result.latency.p95,
    latencyP99: result.latency.p99,
    latencyAvg: result.latency.average,
    totalRequests: result.requests.total,
    errors: result.errors,
    timeouts: result.timeouts,
    non2xx: result.non2xx,
    duration: result.duration,
    connections: result.connections,
  };
}

async function runHealthScenario(config: ScaleTestConfig): Promise<ScenarioResult> {
  console.log("\n--- Scenario: health (GET /health) ---");
  const result = await autocannon({
    url: `${config.baseUrl}/health`,
    connections: config.connections,
    duration: config.duration,
    headers: makeHeaders(config.apiKey),
  });
  return formatResult(result, "health");
}

async function runIssueScenario(config: ScaleTestConfig): Promise<ScenarioResult> {
  console.log("\n--- Scenario: issue (POST /credentials/issue) ---");
  const result = await autocannon({
    url: `${config.baseUrl}/credentials/issue`,
    method: "POST",
    connections: config.connections,
    duration: config.duration,
    headers: makeHeaders(config.apiKey),
    body: JSON.stringify(ISSUE_PAYLOAD),
  });
  return formatResult(result, "issue");
}

async function runVerifyScenario(config: ScaleTestConfig): Promise<ScenarioResult> {
  console.log("\n--- Scenario: verify (POST /credentials/verify) ---");
  // First issue a credential to get something to verify
  console.log("  Pre-step: issuing a credential to use for verification...");
  const issueRes = await fetch(`${config.baseUrl}/credentials/issue`, {
    method: "POST",
    headers: makeHeaders(config.apiKey),
    body: JSON.stringify({
      ...ISSUE_PAYLOAD,
      proofFormat: "data-integrity",
    }),
  });
  if (!issueRes.ok) {
    const errText = await issueRes.text();
    throw new Error(`Pre-step issue failed (${issueRes.status}): ${errText}`);
  }
  const issued = (await issueRes.json()) as { credential: Record<string, unknown> };
  const verifyPayload = { credential: JSON.stringify(issued.credential) };

  const result = await autocannon({
    url: `${config.baseUrl}/credentials/verify`,
    method: "POST",
    connections: config.connections,
    duration: config.duration,
    headers: makeHeaders(config.apiKey),
    body: JSON.stringify(verifyPayload),
  });
  return formatResult(result, "verify");
}

async function runMixedScenario(config: ScaleTestConfig): Promise<ScenarioResult> {
  console.log("\n--- Scenario: mixed (70% verify, 20% issue, 10% health) ---");
  // Pre-issue a credential for the verify requests
  console.log("  Pre-step: issuing a credential for verify portion...");
  const issueRes = await fetch(`${config.baseUrl}/credentials/issue`, {
    method: "POST",
    headers: makeHeaders(config.apiKey),
    body: JSON.stringify({
      ...ISSUE_PAYLOAD,
      proofFormat: "data-integrity",
    }),
  });
  if (!issueRes.ok) {
    const errText = await issueRes.text();
    throw new Error(`Pre-step issue failed (${issueRes.status}): ${errText}`);
  }
  const issued = (await issueRes.json()) as { credential: Record<string, unknown> };
  const verifyPayload = JSON.stringify({ credential: JSON.stringify(issued.credential) });
  const issueBody = JSON.stringify(ISSUE_PAYLOAD);

  // Use setupClient to vary request type per connection
  const result = await autocannon({
    url: config.baseUrl,
    connections: config.connections,
    duration: config.duration,
    requests: [
      // 70% verify (7 out of 10 requests in the rotation)
      ...Array.from({ length: 7 }, () => ({
        method: "POST" as const,
        path: "/credentials/verify",
        headers: makeHeaders(config.apiKey),
        body: verifyPayload,
      })),
      // 20% issue (2 out of 10)
      ...Array.from({ length: 2 }, () => ({
        method: "POST" as const,
        path: "/credentials/issue",
        headers: makeHeaders(config.apiKey),
        body: issueBody,
      })),
      // 10% health (1 out of 10)
      {
        method: "GET" as const,
        path: "/health",
        headers: makeHeaders(config.apiKey),
      },
    ],
  });
  return formatResult(result, "mixed");
}

async function runBatchScenario(config: ScaleTestConfig): Promise<ScenarioResult[]> {
  console.log("\n--- Scenario: batch (POST /credentials/batch) ---");
  const results: ScenarioResult[] = [];

  for (const rowCount of [10, 100, 500]) {
    console.log(`  Sub-scenario: batch with ${rowCount} rows`);
    const csv = makeBatchCsv(rowCount);
    const batchPayload = {
      csvContent: csv,
      schemaId: "functional-identity/v1",
      issuerDid: ISSUE_PAYLOAD.issuerDid,
      validFrom: "2025-06-15T00:00:00Z",
      proofFormat: "vc-jwt",
    };

    // For batch, use fewer connections and shorter duration since each
    // request is heavier (spawns N signing operations).
    const batchConnections = Math.max(2, Math.floor(config.connections / 5));
    const batchDuration = Math.max(5, Math.floor(config.duration / 2));

    const result = await autocannon({
      url: `${config.baseUrl}/credentials/batch`,
      method: "POST",
      connections: batchConnections,
      duration: batchDuration,
      headers: makeHeaders(config.apiKey),
      body: JSON.stringify(batchPayload),
    });
    results.push(formatResult(result, `batch-${rowCount}`));
  }

  return results;
}

// ---------------------------------------------------------------------------
// Results reporting
// ---------------------------------------------------------------------------

function printTable(results: ScenarioResult[]): void {
  console.log("\n" + "=".repeat(100));
  console.log("SCALE TEST RESULTS");
  console.log("=".repeat(100));
  console.log(
    [
      "Scenario".padEnd(15),
      "Req/s".padStart(8),
      "p50(ms)".padStart(9),
      "p95(ms)".padStart(9),
      "p99(ms)".padStart(9),
      "Avg(ms)".padStart(9),
      "Total".padStart(8),
      "Errors".padStart(8),
      "Non2xx".padStart(8),
    ].join(" | "),
  );
  console.log("-".repeat(100));

  for (const r of results) {
    console.log(
      [
        r.name.padEnd(15),
        String(r.requestsPerSec.toFixed(1)).padStart(8),
        String(r.latencyP50.toFixed(1)).padStart(9),
        String(r.latencyP95.toFixed(1)).padStart(9),
        String(r.latencyP99.toFixed(1)).padStart(9),
        String(r.latencyAvg.toFixed(1)).padStart(9),
        String(r.totalRequests).padStart(8),
        String(r.errors).padStart(8),
        String(r.non2xx).padStart(8),
      ].join(" | "),
    );
  }

  console.log("=".repeat(100));
}

function printJson(results: ScenarioResult[]): void {
  console.log("\n--- JSON output ---");
  console.log(JSON.stringify(results, null, 2));
}

// ---------------------------------------------------------------------------
// Server readiness check
// ---------------------------------------------------------------------------

async function waitForServer(baseUrl: string, apiKey?: string, maxRetries = 20): Promise<void> {
  const headers = makeHeaders(apiKey);
  // Remove Content-Type for GET requests
  delete headers["Content-Type"];

  for (let i = 0; i < maxRetries; i++) {
    try {
      const res = await fetch(`${baseUrl}/health`, { headers, signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        const body = (await res.json()) as { status: string; signingKeyLoaded: boolean };
        if (body.status === "ok") {
          if (!body.signingKeyLoaded) {
            console.warn(
              "WARNING: Server is running but no signing key is loaded. " +
                "Issue/verify/batch scenarios will fail. Set OPENCRED_KEY_PATH.",
            );
          }
          return;
        }
      }
    } catch {
      // Server not ready yet
    }
    console.log(`Waiting for server at ${baseUrl}... (attempt ${i + 1}/${maxRetries})`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`Server at ${baseUrl} did not become ready after ${maxRetries} attempts`);
}

// ---------------------------------------------------------------------------
// Issuer DID discovery — derive the DID from the server's signing key
// ---------------------------------------------------------------------------

async function discoverIssuerDid(baseUrl: string, apiKey?: string): Promise<string> {
  const headers = makeHeaders(apiKey);
  delete headers["Content-Type"];

  const res = await fetch(`${baseUrl}/keys`, { headers, signal: AbortSignal.timeout(5000) });
  if (!res.ok) {
    throw new Error(`GET /keys failed (${res.status}): ${await res.text()}`);
  }
  const body = (await res.json()) as { keys: Array<{ id: string }> };
  if (!body.keys || body.keys.length === 0) {
    throw new Error("No signing keys configured on the server. Set OPENCRED_KEY_PATH.");
  }
  // The key id is a verification method (e.g. did:key:z6Mk...#z6Mk...).
  // The issuer DID is the part before the fragment.
  const verificationMethod = body.keys[0].id;
  const issuerDid = verificationMethod.includes("#")
    ? verificationMethod.split("#")[0]
    : verificationMethod;
  return issuerDid;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const config = parseArgs();

  console.log("OpenCred Scale Test");
  console.log("=".repeat(50));
  console.log(`  Base URL:    ${config.baseUrl}`);
  console.log(`  Auth:        ${config.apiKey ? "API key" : "none (dev mode)"}`);
  console.log(`  Duration:    ${config.duration}s per scenario`);
  console.log(`  Connections: ${config.connections}`);
  console.log(`  Scenarios:   ${config.scenarios.join(", ")}`);
  console.log("=".repeat(50));

  // Wait for server to be ready
  await waitForServer(config.baseUrl, config.apiKey);
  console.log("Server is ready.\n");

  // Discover the issuer DID from the server's signing key
  const issuerDid = await discoverIssuerDid(config.baseUrl, config.apiKey);
  console.log(`  Issuer DID:  ${issuerDid}\n`);
  ISSUE_PAYLOAD = { ...ISSUE_PAYLOAD, issuerDid };

  const allResults: ScenarioResult[] = [];

  for (const scenario of config.scenarios) {
    try {
      switch (scenario) {
        case "health":
          allResults.push(await runHealthScenario(config));
          break;
        case "issue":
          allResults.push(await runIssueScenario(config));
          break;
        case "verify":
          allResults.push(await runVerifyScenario(config));
          break;
        case "mixed":
          allResults.push(await runMixedScenario(config));
          break;
        case "batch":
          allResults.push(...(await runBatchScenario(config)));
          break;
        default:
          console.warn(`Unknown scenario: ${scenario} — skipping`);
      }
    } catch (err) {
      console.error(`Scenario "${scenario}" failed:`, err instanceof Error ? err.message : err);
    }
  }

  // Print results
  if (allResults.length > 0) {
    printTable(allResults);
    printJson(allResults);
  } else {
    console.log("\nNo scenarios completed successfully.");
  }
}

main().catch((err) => {
  console.error("Scale test failed:", err);
  process.exit(1);
});
