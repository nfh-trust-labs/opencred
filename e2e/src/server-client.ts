/**
 * Minimal typed HTTP client for the OpenCred server's matrix-relevant
 * endpoints. Deliberately thin — the harness asserts behaviour, the
 * client just moves JSON.
 */
import { API_KEY } from "./docker.js";

export type ProofFormat = "vc-jwt" | "data-integrity" | "sd-jwt-vc";

export interface IssueResult {
  status: number;
  /** JSON envelope (vc-jwt / data-integrity) or compact token string (sd-jwt-vc). */
  credential?: Record<string, unknown> | string;
  error?: { code: string; message: string };
}

async function post(
  baseUrl: string,
  path: string,
  body: unknown,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${baseUrl}/v1${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

export async function issueCredential(
  baseUrl: string,
  proofFormat: ProofFormat,
  subject: Record<string, unknown>,
  overrides: Record<string, unknown> = {},
): Promise<IssueResult> {
  const { status, json } = await post(baseUrl, "/credentials/issue", {
    schemaId: "functional-identity/v1",
    validFrom: "2026-06-01T00:00:00Z",
    credentialSubject: {
      name: "Matrix Holder",
      role: "Tester",
      validFrom: "2026-06-01T00:00:00Z",
      ...subject,
    },
    proofFormat,
    ...overrides,
  });
  return {
    status,
    credential: json.credential as IssueResult["credential"],
    error: json.error as IssueResult["error"],
  };
}

export async function verifyViaServer(
  baseUrl: string,
  credential: Record<string, unknown> | string,
): Promise<{ valid: boolean; code: string; checks: Array<{ name: string; passed: boolean }> }> {
  const { json } = await post(baseUrl, "/credentials/verify", {
    credential: typeof credential === "string" ? credential : JSON.stringify(credential),
  });
  return json as unknown as {
    valid: boolean;
    code: string;
    checks: Array<{ name: string; passed: boolean }>;
  };
}

export async function packageCredential(
  baseUrl: string,
  credential: Record<string, unknown> | string,
  formats: string[],
): Promise<Array<{ format: string; data: string; encoding?: string }>> {
  const { json } = await post(baseUrl, "/credentials/package", { credential, formats });
  return json.outputs as Array<{ format: string; data: string; encoding?: string }>;
}
