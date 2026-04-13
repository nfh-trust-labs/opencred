import type { Hono } from "hono";
import type {
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
  JWK,
} from "@opencred/did";

export {
  generateTestKey,
  createTestApp,
  FUNCTIONAL_IDENTITY_SUBJECT,
  VALID_ISSUE_REQUEST,
  DEFAULT_TEST_API_KEY,
} from "../helpers.js";
export type { TestKeyPair } from "../helpers.js";

export async function issueViaApp(
  app: Hono,
  body: Record<string, unknown>,
  apiKey?: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }
  const res = await app.request("/v1/credentials/issue", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

export async function verifyViaApp(
  app: Hono,
  credential: unknown,
  apiKey?: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }
  const res = await app.request("/v1/credentials/verify", {
    method: "POST",
    headers,
    body: JSON.stringify({ credential }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

export function createMockResolver(did: string, publicKeyJwk: JWK): DIDResolver {
  const vmId = `${did}#key-0`;
  const verificationMethod: VerificationMethod = {
    id: vmId,
    type: "JsonWebKey",
    controller: did,
    publicKeyJwk,
  };
  return {
    resolve: async (inputDid: string): Promise<DIDResolutionResult> => {
      if (inputDid !== did) {
        return {
          didDocument: null,
          didResolutionMetadata: { error: "notFound" },
          didDocumentMetadata: {},
        };
      }
      return {
        didDocument: {
          "@context": "https://www.w3.org/ns/did/v1",
          id: did,
          verificationMethod: [verificationMethod],
          assertionMethod: [vmId],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

export function createMockDediClient(
  store: Map<string, boolean>,
): { checkRevocation: (hash: string) => Promise<{ revoked: boolean }> } {
  return {
    checkRevocation: async (hash: string) => ({
      revoked: store.get(hash) ?? false,
    }),
  };
}
