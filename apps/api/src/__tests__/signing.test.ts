import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Hono } from "hono";
import { generateKeyPairSync, createSign } from "node:crypto";
import { createCapabilityToken } from "@opencred/auth";
import { TTLStore } from "@opencred/state";
import { createSigningRoutes, type SigningSession } from "../routes/signing.js";
import { authMiddleware } from "../middleware/auth.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

const TEST_SECRET = new TextEncoder().encode("test-secret-key-that-is-at-least-32-bytes-long!!");
const logger = makeTestLogger();

const issuerKeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
const issuerPublicJwk = issuerKeyPair.publicKey.export({ format: "jwk" }) as {
  kty: string; crv: string; x: string; y: string;
};
const wrongKeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" });

interface ErrorBody { error: { code: string; message: string; validationErrors?: unknown[] } }
interface BuildResponse { sessionId: string; unsignedCredential: Record<string, unknown>; dataToSign: string; proofConfig: Record<string, unknown> }
interface PackageResponse { credential: Record<string, unknown> & { proof: Record<string, unknown> }; formats: { jsonld: Record<string, unknown> } }

let sessionStore: TTLStore<SigningSession>;

function createTestApp(store?: TTLStore<SigningSession>) {
  const ss = store ?? sessionStore;
  const app = new Hono();
  app.use("/vc/*", authMiddleware(
    { verificationKey: TEST_SECRET, issuer: "opencred", algorithms: ["HS256"] },
    "credentials:write",
  ));
  app.route("/vc", createSigningRoutes({ sessionStore: ss }));
  app.onError(errorHandler(logger));
  return app;
}

async function makeToken(scope: string[] = ["credentials:write"]) {
  return createCapabilityToken({
    subject: "issuer-1", issuer: "opencred", expiresInSeconds: 3600,
    scope, namespace: "default", signingKey: TEST_SECRET, algorithm: "HS256",
  });
}

function validBuildPayload(overrides: Record<string, unknown> = {}) {
  return {
    schema: "education",
    issuer: "did:web:university.example",
    publicKey: issuerPublicJwk,
    credentialSubject: {
      name: "Jane Doe", degree: "BSc Computer Science",
      institution: "Test University", dateConferred: "2025-06-15",
    },
    validFrom: "2025-07-01T00:00:00Z",
    ...overrides,
  };
}

function signDataToSign(dataToSignB64: string, privateKey = issuerKeyPair.privateKey): string {
  const dataToSign = Buffer.from(dataToSignB64, "base64url");
  const signer = createSign("SHA256");
  signer.update(dataToSign);
  const sig = signer.sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  return Buffer.from(sig).toString("base64url");
}

async function doBuild(
  app: ReturnType<typeof createTestApp>, token: string,
  payload: Record<string, unknown> = validBuildPayload(),
): Promise<{ res: Response; body: BuildResponse }> {
  const res = await app.request("/vc/build", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  const body = (await res.json()) as BuildResponse;
  return { res, body };
}

beforeEach(() => { sessionStore = new TTLStore<SigningSession>(60_000, 600_000); });
afterEach(() => { sessionStore.destroy(); });

describe("POST /build (interface signing step 1)", () => {
  it("returns 401 without auth token", async () => {
    const app = createTestApp();
    const res = await app.request("/vc/build", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validBuildPayload()),
    });
    expect(res.status).toBe(401);
  });

  it("returns 403 with wrong scope", async () => {
    const token = await createCapabilityToken({
      subject: "issuer-1", issuer: "opencred", expiresInSeconds: 3600,
      scope: ["credentials:read"], namespace: "default",
      signingKey: TEST_SECRET, algorithm: "HS256",
    });
    const app = createTestApp();
    const res = await app.request("/vc/build", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(validBuildPayload()),
    });
    expect(res.status).toBe(403);
  });

  it("builds an unsigned VC and returns sessionId + dataToSign", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { res, body } = await doBuild(app, token);
    expect(res.status).toBe(201);
    expect(body.sessionId).toBeDefined();
    expect(body.dataToSign).toBeDefined();
    expect(body.proofConfig).toBeDefined();
    expect(body.unsignedCredential).toBeDefined();
    const vc = body.unsignedCredential;
    expect(vc["@context"]).toBeDefined();
    expect(vc.type).toContain("VerifiableCredential");
    expect(vc.issuer).toBe("did:web:university.example");
    expect(vc.validFrom).toBe("2025-07-01T00:00:00Z");
    expect(body.proofConfig.type).toBe("DataIntegrityProof");
    expect(body.proofConfig.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(body.proofConfig.proofPurpose).toBe("assertionMethod");
  });

  it("uses custom verificationMethod when provided", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body } = await doBuild(app, token, validBuildPayload({
      verificationMethod: "did:web:university.example#my-key",
    }));
    expect(body.proofConfig.verificationMethod).toBe("did:web:university.example#my-key");
  });

  it("defaults verificationMethod to issuer#key-0", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body } = await doBuild(app, token);
    expect(body.proofConfig.verificationMethod).toBe("did:web:university.example#key-0");
  });

  it("adds revocation status when revocationRegistryUrl is provided", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body } = await doBuild(app, token, validBuildPayload({
      revocationRegistryUrl: "https://dedi.example/revocations/test",
    }));
    const status = body.unsignedCredential.credentialStatus as { id: string; type: string; statusPurpose: string };
    expect(status.id).toBe("https://dedi.example/revocations/test");
    expect(status.type).toBe("DeDiRevocationListStatusV1");
    expect(status.statusPurpose).toBe("revocation");
  });

  it("adds validUntil when provided", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body } = await doBuild(app, token, validBuildPayload({ validUntil: "2027-07-01T00:00:00Z" }));
    expect(body.unsignedCredential.validUntil).toBe("2027-07-01T00:00:00Z");
  });

  it("sets credentialSchema reference", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body } = await doBuild(app, token);
    const schema = body.unsignedCredential.credentialSchema as { id: string; type: string };
    expect(schema.id).toBe("https://opencred.dev/schemas/education/v1");
    expect(schema.type).toBe("JsonSchema");
  });

  it("rejects invalid schema", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const res = await app.request("/vc/build", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(validBuildPayload({ schema: "nonexistent" })),
    });
    expect(res.status).toBe(404);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("NOT_FOUND");
  });

  it("rejects subject that fails schema validation", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const res = await app.request("/vc/build", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(validBuildPayload({ credentialSubject: { name: "Jane" } })),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("SCHEMA_VALIDATION_ERROR");
  });

  it("rejects non-HTTPS revocationRegistryUrl", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const res = await app.request("/vc/build", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(validBuildPayload({ revocationRegistryUrl: "http://not-secure.example/r" })),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("HTTPS");
  });

  it("rejects unparseable revocationRegistryUrl", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const res = await app.request("/vc/build", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(validBuildPayload({ revocationRegistryUrl: "not-a-url" })),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("valid URL");
  });

  it("rejects missing required fields", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const res = await app.request("/vc/build", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ schema: "education" }),
    });
    expect(res.status).toBe(400);
  });

  it("rejects invalid publicKey (wrong curve)", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const res = await app.request("/vc/build", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(validBuildPayload({ publicKey: { kty: "EC", crv: "P-384", x: "abc", y: "def" } })),
    });
    expect(res.status).toBe(400);
  });
});

describe("POST /package (interface signing step 2)", () => {
  it("returns 401 without auth token", async () => {
    const app = createTestApp();
    const res = await app.request("/vc/package", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sessionId: "00000000-0000-0000-0000-000000000000", signature: "test" }),
    });
    expect(res.status).toBe(401);
  });

  it("returns 410 for non-existent session", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const res = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: "00000000-0000-0000-0000-000000000000", signature: "AAAA" }),
    });
    expect(res.status).toBe(410);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("SESSION_EXPIRED");
  });

  it("returns 410 for expired session", async () => {
    const shortStore = new TTLStore<SigningSession>(1, 600_000);
    const token = await makeToken();
    const app = createTestApp(shortStore);
    const { body: buildBody } = await doBuild(app, token);
    expect(buildBody.sessionId).toBeDefined();
    await new Promise((r) => setTimeout(r, 50));
    const sig = signDataToSign(buildBody.dataToSign);
    const res = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: buildBody.sessionId, signature: sig }),
    });
    expect(res.status).toBe(410);
    shortStore.destroy();
  });

  it("rejects invalid signature (wrong key)", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body: buildBody } = await doBuild(app, token);
    expect(buildBody.sessionId).toBeDefined();
    const badSig = signDataToSign(buildBody.dataToSign, wrongKeyPair.privateKey);
    const res = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: buildBody.sessionId, signature: badSig }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("Signature verification failed");
  });

  it("rejects signature with wrong length", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body: buildBody } = await doBuild(app, token);
    expect(buildBody.sessionId).toBeDefined();
    const shortSig = Buffer.from(new Uint8Array(32)).toString("base64url");
    const res = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: buildBody.sessionId, signature: shortSig }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.message).toContain("64 bytes");
  });

  it("rejects invalid sessionId format", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const res = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: "not-a-uuid", signature: "AAAA" }),
    });
    expect(res.status).toBe(400);
  });

  it("session is one-time use (deleted after package)", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body: buildBody } = await doBuild(app, token);
    expect(buildBody.sessionId).toBeDefined();
    const sig = signDataToSign(buildBody.dataToSign);
    const res1 = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: buildBody.sessionId, signature: sig }),
    });
    expect(res1.status).toBe(200);
    const res2 = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: buildBody.sessionId, signature: sig }),
    });
    expect(res2.status).toBe(410);
  });
});

describe("Full round-trip: build -> sign -> package", () => {
  it("produces a valid VerifiableCredential with Data Integrity proof", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { res: buildRes, body: buildBody } = await doBuild(app, token);
    expect(buildRes.status).toBe(201);
    const sig = signDataToSign(buildBody.dataToSign);
    const packageRes = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: buildBody.sessionId, signature: sig }),
    });
    expect(packageRes.status).toBe(200);
    const packageBody = (await packageRes.json()) as PackageResponse;
    const vc = packageBody.credential;
    expect(vc["@context"]).toBeDefined();
    expect(vc.type).toContain("VerifiableCredential");
    expect(vc.issuer).toBe("did:web:university.example");
    expect(vc.proof).toBeDefined();
    expect(vc.proof.type).toBe("DataIntegrityProof");
    expect(vc.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(vc.proof.proofPurpose).toBe("assertionMethod");
    expect(vc.proof.proofValue).toBeDefined();
    expect(typeof vc.proof.proofValue).toBe("string");
    expect(packageBody.formats.jsonld).toEqual(vc);
  });

  it("works with revocationRegistryUrl and validUntil", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { body: buildBody } = await doBuild(app, token, validBuildPayload({
      revocationRegistryUrl: "https://dedi.example/revocations/test",
      validUntil: "2027-07-01T00:00:00Z",
    }));
    expect(buildBody.sessionId).toBeDefined();
    const sig = signDataToSign(buildBody.dataToSign);
    const packageRes = await app.request("/vc/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ sessionId: buildBody.sessionId, signature: sig }),
    });
    expect(packageRes.status).toBe(200);
    const body = (await packageRes.json()) as PackageResponse;
    const vc = body.credential;
    expect(vc.validUntil).toBe("2027-07-01T00:00:00Z");
    const status = vc.credentialStatus as { id: string; type: string };
    expect(status.id).toBe("https://dedi.example/revocations/test");
    expect(status.type).toBe("DeDiRevocationListStatusV1");
  });

  it("works with different schema types", async () => {
    const token = await makeToken();
    const app = createTestApp();
    const { res } = await doBuild(app, token, {
      schema: "employment",
      issuer: "did:web:employer.example",
      publicKey: issuerPublicJwk,
      credentialSubject: {
        name: "John Smith", employer: "Tech Corp",
        position: "Engineer", startDate: "2024-01-15",
      },
      validFrom: "2024-01-15T00:00:00Z",
    });
    expect(res.status).toBe(201);
  });
});
