/**
 * DeDi key-lifecycle cells — publish → issue → verify → rotate → revoke,
 * against a REAL DeDi staging namespace (the dedi-client's SSRF guard
 * refuses loopback by design, so there is no local-mock path).
 *
 * Env (all required, suite skips loudly otherwise):
 *   OPENCRED_E2E_IMAGE            built server image tag
 *   OPENCRED_E2E_DEDI_BASE_URL    public DeDi instance (staging)
 *   OPENCRED_E2E_DEDI_NAMESPACE   verified namespace = issuer domain.
 *                                 Pick one whose `https://<ns>/.well-known/did.json`
 *                                 does NOT resolve, so the verify-sdk's DeDi
 *                                 fallback path is what gets exercised.
 *   OPENCRED_E2E_DEDI_API_KEY     write-capable API key for that namespace
 *
 * Each run generates fresh keys, so verification-method record names and
 * credential hashes never collide across runs.
 */
import { describe, it, expect, afterAll } from "vitest";
import { createVerifier } from "@opencred/verify";
import {
  E2E_IMAGE,
  dockerAvailable,
  startServer,
  type ServerContainer,
  API_KEY,
} from "./docker.js";
import { issueCredential, verifyViaServer } from "./server-client.js";

const DEDI_BASE_URL = process.env.OPENCRED_E2E_DEDI_BASE_URL;
const DEDI_NAMESPACE = process.env.OPENCRED_E2E_DEDI_NAMESPACE;
const DEDI_API_KEY = process.env.OPENCRED_E2E_DEDI_API_KEY;

const runnable =
  Boolean(E2E_IMAGE && DEDI_BASE_URL && DEDI_NAMESPACE && DEDI_API_KEY) && dockerAvailable();
if (!runnable) {
  // eslint-disable-next-line no-console
  console.warn(
    "[e2e-dedi-lifecycle] SKIPPED — set OPENCRED_E2E_IMAGE, OPENCRED_E2E_DEDI_BASE_URL, " +
      "OPENCRED_E2E_DEDI_NAMESPACE, OPENCRED_E2E_DEDI_API_KEY and ensure docker is running.",
  );
}

const dediEnv = (keyIndex: number): Record<string, string> => ({
  OPENCRED_DEDI_BASE_URL: DEDI_BASE_URL!,
  OPENCRED_DEDI_NAMESPACE: DEDI_NAMESPACE!,
  OPENCRED_DEDI_AUTH_TYPE: "api-key",
  OPENCRED_DEDI_API_KEY: DEDI_API_KEY!,
  OPENCRED_DEDI_HOST_DID_DOC: "true",
  OPENCRED_ISSUER_DID_METHOD: "web",
  OPENCRED_ISSUER_DOMAIN: DEDI_NAMESPACE!,
  OPENCRED_DIDWEB_KEY_INDEX: String(keyIndex),
});

async function postKeys(
  baseUrl: string,
  path: string,
  body: Record<string, unknown>,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${baseUrl}/v1${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

describe.runIf(runnable)("DeDi key lifecycle (did:web, staging namespace)", () => {
  const did = `did:web:${DEDI_NAMESPACE}`;
  const vm = (index: number) => `${did}#key-${index}`;

  // DeDi-aware verifier — revocation + key-status checks active, did:web
  // resolution falls back to DeDi when the canonical fetch fails.
  const verify = createVerifier({
    dedi: {
      baseUrl: DEDI_BASE_URL!,
      namespace: DEDI_NAMESPACE!,
      auth: { type: "api-key", apiKey: DEDI_API_KEY! },
    },
  });

  let serverA: ServerContainer | undefined;
  let serverB: ServerContainer | undefined;
  let credA: Record<string, unknown> | string;
  let credB: Record<string, unknown> | string;

  afterAll(() => {
    serverA?.stop();
    serverB?.stop();
  });

  it("1. publish active key (index 0) → DeDi record + hosted did.json", async () => {
    serverA = await startServer("P-256", 3120, dediEnv(0));
    const { status, json } = await postKeys(serverA.baseUrl, "/keys/publish", {});
    expect(status, JSON.stringify(json)).toBe(200);
    expect(json.keyId).toBe(vm(0));
    expect(json.didDocumentStored).toBe(true);
  });

  it("2. issue under key-0 → verifies VALID through the DeDi-aware SDK", async () => {
    const issued = await issueCredential(serverA!.baseUrl, "vc-jwt", {
      id: "did:example:lifecycle-holder-a",
    });
    expect(issued.status, JSON.stringify(issued.error)).toBe(200);
    credA = issued.credential!;

    const result = await verify(credA as never);
    expect(result.code, JSON.stringify(result.checks)).toBe("VALID");
    // Revocation check must have actually run (DeDi configured).
    const revocation = result.checks.find((c) => c.name === "revocation");
    expect(revocation?.passed).toBe(true);
    expect(revocation?.detail ?? "").not.toMatch(/NOT checked/);
  });

  it("3. rotate to key-1 → old key marked rotated, old credential still VALID", async () => {
    // Rotation workflow per docs: deploy the NEW key (fresh container,
    // index 1), then call /v1/keys/rotate naming the previous VM.
    serverA!.stop();
    serverB = await startServer("P-256", 3121, dediEnv(1));
    const { status, json } = await postKeys(serverB.baseUrl, "/keys/rotate", {
      previousVerificationMethod: vm(0),
      hostDidDocument: true,
    });
    expect(status, JSON.stringify(json)).toBe(200);
    expect(json.rotated).toBe(true);
    expect(json.currentKeyId).toBe(vm(1));

    // Credential signed under the rotated (not revoked) key stays VALID.
    const oldResult = await verify(credA as never);
    expect(oldResult.code, JSON.stringify(oldResult.checks)).toBe("VALID");

    // New credential under key-1 verifies too.
    const issued = await issueCredential(serverB.baseUrl, "vc-jwt", {
      id: "did:example:lifecycle-holder-b",
    });
    expect(issued.status, JSON.stringify(issued.error)).toBe(200);
    credB = issued.credential!;
    const newResult = await verify(credB as never);
    expect(newResult.code, JSON.stringify(newResult.checks)).toBe("VALID");
  });

  it("4. revoke credential B → B is REVOKED, A stays VALID", async () => {
    const envelope = credB as Record<string, unknown>;
    const { status, json } = await postKeys(serverB!.baseUrl, "/credentials/revoke", {
      credential: envelope,
      reason: "e2e-matrix lifecycle test",
    });
    expect(status, JSON.stringify(json)).toBe(200);

    const revoked = await verify(credB as never);
    expect(revoked.code, JSON.stringify(revoked.checks)).toBe("REVOKED");

    const stillValid = await verify(credA as never);
    expect(stillValid.code).toBe("VALID");
  });

  it("5. revoke old key-0 → credential A is REVOKED, B's key unaffected", async () => {
    const { status, json } = await postKeys(serverB!.baseUrl, "/keys/revoke", {
      verificationMethod: vm(0),
    });
    expect(status, JSON.stringify(json)).toBe(200);

    const result = await verify(credA as never);
    expect(result.code, JSON.stringify(result.checks)).toBe("REVOKED");
  });

  it("6. without DeDi config, the SDK surfaces 'revocation NOT checked'", async () => {
    const offlineVerify = createVerifier();
    const result = await offlineVerify(credA as never);
    const revocation = result.checks.find((c) => c.name === "revocation");
    expect(revocation?.detail ?? "").toMatch(/NOT checked/);
  });

  it("server /verify with DeDi also rejects the revoked credential", async () => {
    const result = await verifyViaServer(serverB!.baseUrl, credB);
    expect(result.code).toBe("REVOKED");
  });
});
