import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import dns from "node:dns";
import type { Hono } from "hono";
import { generateDidWebDocument } from "@opencred/did";
import type { JWK } from "@opencred/did";
import { signCredential } from "@opencred/crypto";
import type { UnsignedCredential } from "@opencred/vc-core";
import { setActiveSigner } from "../../signing/key-manager.js";
import {
  generateTestKey,
  createTestApp,
  verifyViaApp,
} from "./helpers.js";
import type { TestKeyPair } from "./helpers.js";

let app: Hono;
let testKey: TestKeyPair;

const TEST_DID = "did:web:example.com";
const PUBLIC_IP = "93.184.216.34";

let originalFetch: typeof globalThis.fetch;

beforeAll(() => {
  testKey = generateTestKey();
  originalFetch = globalThis.fetch;
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);

  vi.spyOn(dns.promises, "resolve4").mockResolvedValue([PUBLIC_IP]);
  vi.spyOn(dns.promises, "resolve6").mockRejectedValue(new Error("no AAAA records"));
  globalThis.fetch = vi.fn();
});

afterEach(() => {
  vi.restoreAllMocks();
  globalThis.fetch = originalFetch;
});

function getFetchMock(): ReturnType<typeof vi.fn> {
  return globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
}

function getDnsResolve4Mock(): ReturnType<typeof vi.fn> {
  return dns.promises.resolve4 as unknown as ReturnType<typeof vi.fn>;
}

function createSignedCredential(
  key: TestKeyPair,
  issuerDid: string,
): Promise<import("@opencred/vc-core").VerifiableCredential> {
  const verificationMethodId = `${issuerDid}#key-0`;
  const unsignedVC: UnsignedCredential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: `urn:uuid:test-did-web-${Date.now()}`,
    type: ["VerifiableCredential"],
    issuer: issuerDid,
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder",
      name: "Test Subject",
    },
  };
  return signCredential(
    unsignedVC,
    {
      id: verificationMethodId,
      privateKey: key.privateKey,
      publicKey: key.publicKey,
      algorithm: "P-256",
    },
    {
      verificationMethod: verificationMethodId,
      proofPurpose: "assertionMethod",
    },
  );
}

function mockFetchDidDocument(didDoc: Record<string, unknown>): void {
  getFetchMock().mockResolvedValue(
    new Response(JSON.stringify(didDoc), {
      status: 200,
      headers: { "content-type": "application/did+json" },
    }),
  );
}

describe("did:web verification — valid resolution", () => {
  it("verifies a credential with mocked did:web resolution", async () => {
    const jwk = testKey.publicKey.export({ format: "jwk" }) as JWK;
    const didDocument = generateDidWebDocument(TEST_DID, jwk);
    mockFetchDidDocument(didDocument as unknown as Record<string, unknown>);

    const signedVC = await createSignedCredential(testKey, TEST_DID);

    const res = await verifyViaApp(app, JSON.stringify(signedVC));
    expect(res.status).toBe(200);
    const result = (await res.json()) as { valid: boolean; code: string };
    expect(result.valid).toBe(true);
    expect(result.code).toBe("VALID");

    expect(getDnsResolve4Mock()).toHaveBeenCalledWith("example.com");
    expect(getFetchMock()).toHaveBeenCalledWith(
      "https://example.com/.well-known/did.json",
      expect.objectContaining({ redirect: "error" }),
    );
  });
});

describe("did:web verification — wrong key", () => {
  it("returns INVALID when DID doc has a different key", async () => {
    const wrongKey = generateTestKey();
    const wrongJwk = wrongKey.publicKey.export({ format: "jwk" }) as JWK;
    const didDocument = generateDidWebDocument(TEST_DID, wrongJwk);
    mockFetchDidDocument(didDocument as unknown as Record<string, unknown>);

    const signedVC = await createSignedCredential(testKey, TEST_DID);

    const res = await verifyViaApp(app, JSON.stringify(signedVC));
    expect(res.status).toBe(200);
    const result = (await res.json()) as { valid: boolean; code: string };
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID");
  });
});

describe("did:web verification — SSRF protection", () => {
  it("returns UNRESOLVABLE when DNS resolves to a private IP", async () => {
    getDnsResolve4Mock().mockResolvedValue(["127.0.0.1"]);

    const jwk = testKey.publicKey.export({ format: "jwk" }) as JWK;
    const didDocument = generateDidWebDocument(TEST_DID, jwk);
    mockFetchDidDocument(didDocument as unknown as Record<string, unknown>);

    const signedVC = await createSignedCredential(testKey, TEST_DID);

    const res = await verifyViaApp(app, JSON.stringify(signedVC));
    expect(res.status).toBe(200);
    const result = (await res.json()) as { valid: boolean; code: string };
    expect(result.valid).toBe(false);
    expect(result.code).toBe("UNRESOLVABLE");
    expect(getFetchMock()).not.toHaveBeenCalled();
  });
});

describe("did:web verification — HTTP 404", () => {
  it("returns UNRESOLVABLE when DID document fetch returns 404", async () => {
    getFetchMock().mockResolvedValue(
      new Response("Not Found", { status: 404 }),
    );

    const signedVC = await createSignedCredential(testKey, TEST_DID);

    const res = await verifyViaApp(app, JSON.stringify(signedVC));
    expect(res.status).toBe(200);
    const result = (await res.json()) as { valid: boolean; code: string };
    expect(result.valid).toBe(false);
    expect(result.code).toBe("UNRESOLVABLE");
  });
});
