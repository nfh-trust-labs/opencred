import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import type { Hono } from "hono";
import { computeRevocationHash } from "@opencred/crypto";
import { verifyCredential } from "@opencred/verification";
import { setActiveSigner } from "../../signing/key-manager.js";
import {
  generateTestKey,
  createTestApp,
  VALID_ISSUE_REQUEST,
  issueViaApp,
  verifyViaApp,
  createMockDediClient,
  createMockResolver,
} from "./helpers.js";
import type { TestKeyPair } from "./helpers.js";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
});

describe("revocation lifecycle — data-integrity", () => {
  it("issue -> verify VALID -> revoke -> verify REVOKED", async () => {
    const issuerDid = testKey.signer.id.split("#")[0];
    const signerId = testKey.signer.id;
    const jwk = testKey.publicKey.export({ format: "jwk" });

    const issueRes = await issueViaApp(app, {
      ...VALID_ISSUE_REQUEST,
      issuerDid,
      proofFormat: "data-integrity",
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };
    const credential = issued.credential;

    const verifyRes = await verifyViaApp(app, JSON.stringify(credential));
    expect(verifyRes.status).toBe(200);
    const firstResult = (await verifyRes.json()) as { valid: boolean; code: string };
    expect(firstResult.valid).toBe(true);
    expect(firstResult.code).toBe("VALID");

    const hash = computeRevocationHash(credential);
    expect(typeof hash).toBe("string");
    expect(hash.length).toBeGreaterThan(0);

    const revocationStore = new Map<string, boolean>();
    revocationStore.set(hash, true);
    const mockDedi = createMockDediClient(revocationStore);
    const mockResolver = createMockResolver(
      issuerDid,
      jwk as import("@opencred/did").JWK,
      signerId,
    );

    const revokedResult = await verifyCredential(credential as Record<string, unknown>, {
      didResolver: mockResolver,
      dediClient: mockDedi,
    });
    expect(revokedResult.code).toBe("REVOKED");
    expect(revokedResult.verified).toBe(false);
    expect(revokedResult.checks.some((c) => c.name === "revocation" && !c.passed)).toBe(true);
  });
});

describe("revocation lifecycle — vc-jwt", () => {
  it("issue -> verify VALID -> revoke -> verify REVOKED", async () => {
    const issuerDid = testKey.signer.id.split("#")[0];
    const signerId = testKey.signer.id;
    const jwk = testKey.publicKey.export({ format: "jwk" });

    const issueRes = await issueViaApp(app, {
      ...VALID_ISSUE_REQUEST,
      issuerDid,
      proofFormat: "vc-jwt",
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };
    const credential = issued.credential;

    const jwtString = (credential as { proof: { jwt: string } }).proof.jwt;

    const mockResolver = createMockResolver(
      issuerDid,
      jwk as import("@opencred/did").JWK,
      signerId,
    );

    const validResult = await verifyCredential(jwtString, {
      didResolver: mockResolver,
    });
    expect(validResult.code).toBe("VALID");
    expect(validResult.verified).toBe(true);

    const payloadB64 = jwtString.split(".")[1];
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString()) as {
      vc: Record<string, unknown>;
    };
    const hash = computeRevocationHash(payload.vc);
    const revocationStore = new Map<string, boolean>();
    revocationStore.set(hash, true);
    const mockDedi = createMockDediClient(revocationStore);

    const revokedResult = await verifyCredential(jwtString, {
      didResolver: mockResolver,
      dediClient: mockDedi,
    });
    expect(revokedResult.code).toBe("REVOKED");
    expect(revokedResult.verified).toBe(false);
  });
});

describe("revocation hash stability", () => {
  it("same credential data produces the same hash", async () => {
    const issuerDid = testKey.signer.id.split("#")[0];

    const issueRes = await issueViaApp(app, {
      ...VALID_ISSUE_REQUEST,
      issuerDid,
      proofFormat: "data-integrity",
    });
    expect(issueRes.status).toBe(200);
    const issued = (await issueRes.json()) as { credential: Record<string, unknown> };

    const hash1 = computeRevocationHash(issued.credential);
    const hash2 = computeRevocationHash(issued.credential);
    expect(hash1).toBe(hash2);
    expect(typeof hash1).toBe("string");
    expect(hash1.length).toBe(64);
  });
});
