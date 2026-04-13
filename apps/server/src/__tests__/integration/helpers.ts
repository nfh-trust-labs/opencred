import type { Hono } from "hono";
import type { DIDResolver, DIDResolutionResult, DIDDocument, VerificationMethod, JWK } from "@opencred/did";

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
): Promise<Response> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }
  return app.request("/v1/credentials/issue", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

export async function verifyViaApp(
  app: Hono,
  credential: unknown,
  apiKey?: string,
): Promise<Response> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }
  const credentialStr = typeof credential === "string" ? credential : JSON.stringify(credential);
  return app.request("/v1/credentials/verify", {
    method: "POST",
    headers,
    body: JSON.stringify({ credential: credentialStr }),
  });
}

export function createMockDediClient(
  revocationStore: Map<string, boolean>,
): { queryRevocationHash: (hash: string) => Promise<{ hash: string; revoked: boolean; revokedAt?: string }> } {
  return {
    queryRevocationHash: async (hash: string) => {
      const revoked = revocationStore.get(hash) ?? false;
      if (revoked) {
        return { hash, revoked: true, revokedAt: new Date().toISOString() };
      }
      return { hash, revoked: false };
    },
  };
}

export function createMockResolver(did: string, publicKeyJwk: JWK): DIDResolver {
  const verificationMethodId = `${did}#key-1`;
  const vm: VerificationMethod = {
    id: verificationMethodId,
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
          verificationMethod: [vm],
          assertionMethod: [verificationMethodId],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}
