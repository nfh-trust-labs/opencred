import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { createCapabilityToken } from "@opencred/auth";
import { LocalSigningKeyProvider } from "@opencred/crypto";
import type { DeDiClient } from "@opencred/dedi-client";
import type { DelegationCertificate } from "@opencred/delegation";
import { createCredentialsRoute } from "../routes/credentials.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestConfig, makeTestLogger } from "./helpers.js";

// -------------------------------------------------------------------------
// Test infrastructure
// -------------------------------------------------------------------------

const TEST_SECRET = new TextEncoder().encode("test-secret-key-that-is-at-least-32-bytes-long!!");
const logger = makeTestLogger();

const signingKeyProvider = new LocalSigningKeyProvider();
const activeKey = signingKeyProvider.getActiveKey();

const AUTH_OPTIONS = {
  verificationKey: TEST_SECRET,
  issuer: "opencred",
  algorithms: ["HS256"] as string[],
};

async function makeToken(scope: string[] = ["credentials:issue-delegated"]) {
  return createCapabilityToken({
    subject: "issuer-1",
    issuer: "opencred",
    expiresInSeconds: 3600,
    scope,
    namespace: "default",
    signingKey: TEST_SECRET,
    algorithm: "HS256",
  });
}

// -------------------------------------------------------------------------
// Mock delegation certificate factory
// -------------------------------------------------------------------------

function makeActiveDelegation(overrides: Partial<DelegationCertificate> = {}): DelegationCertificate {
  const now = new Date();
  const validFrom = new Date(now.getTime() - 86400000).toISOString(); // 1 day ago
  const validUntil = new Date(now.getTime() + 86400000).toISOString(); // 1 day from now

  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://opencred.example/ns/delegation/v1",
    ],
    id: "urn:uuid:delegation-1",
    type: ["DelegationCertificate"],
    delegator: {
      id: "https://university.example",
      name: "Example University",
    },
    delegatee: {
      id: activeKey.id,
    },
    scope: {
      credentialTypes: ["education"],
      namespaces: ["education"],
    },
    validFrom,
    validUntil,
    authorisationPath: "dedi-registry",
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: validFrom,
      verificationMethod: "https://university.example#key-1",
      proofPurpose: "assertionMethod",
      proofValue: "zMockProofValue",
    },
    ...overrides,
  };
}

function makeExpiredDelegation(): DelegationCertificate {
  const pastFrom = new Date(Date.now() - 172800000).toISOString(); // 2 days ago
  const pastUntil = new Date(Date.now() - 86400000).toISOString(); // 1 day ago
  return makeActiveDelegation({ validFrom: pastFrom, validUntil: pastUntil });
}

function makeScopeMismatchDelegation(): DelegationCertificate {
  return makeActiveDelegation({
    scope: {
      credentialTypes: ["health"],
      namespaces: ["health"],
    },
  });
}

// -------------------------------------------------------------------------
// Mock DeDi client
// -------------------------------------------------------------------------

function createMockDediClient(delegation: DelegationCertificate | null): DeDiClient {
  return {
    resolveDelegation: vi.fn().mockImplementation(async (id: string) => {
      if (!delegation) {
        throw new Error(`Delegation ${id} not found`);
      }
      return { id, certificate: delegation };
    }),
    registerDelegation: vi.fn().mockResolvedValue({}),
    checkRevocation: vi.fn().mockResolvedValue({ revoked: false }),
    revokeCredential: vi.fn().mockResolvedValue({}),
  } as unknown as DeDiClient;
}

// -------------------------------------------------------------------------
// App factory
// -------------------------------------------------------------------------

function createTestApp(delegation: DelegationCertificate | null = makeActiveDelegation()) {
  const config = makeTestConfig();
  const dediClient = createMockDediClient(delegation);
  const { credentials } = createCredentialsRoute({
    config,
    authOptions: AUTH_OPTIONS,
    signingKeyProvider,
    dediClient,
  });
  const app = new Hono();
  app.route("/credentials", credentials);
  app.onError(errorHandler(logger));
  return { app, dediClient };
}

const VALID_BODY = {
  delegationId: "urn:uuid:delegation-1",
  schema: "education",
  credentialSubject: {
    name: "Jane Doe",
    degree: "Bachelor of Science",
    institution: "Example University",
    dateConferred: "2025-06-15",
  },
  validFrom: "2026-01-01T00:00:00Z",
};

interface ErrorBody {
  error: { code: string; message: string; validationErrors?: unknown[] };
}

interface IssueDelegatedResponse {
  credential: {
    "@context": string[];
    type: string[];
    issuer: string | { id: string; name?: string };
    credentialSubject: Record<string, unknown>;
    validFrom: string;
    validUntil?: string;
    credentialStatus?: Record<string, unknown>;
    proof: Record<string, unknown>;
  };
}

// -------------------------------------------------------------------------
// Tests: Authentication & Authorization
// -------------------------------------------------------------------------

describe("POST /credentials/issue-delegated — auth", () => {
  it("returns 401 without auth token", async () => {
    const { app } = createTestApp();
    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(VALID_BODY),
    });
    expect(res.status).toBe(401);
  });

  it("returns 403 with wrong scope in token", async () => {
    const { app } = createTestApp();
    const token = await makeToken(["credentials:build"]);
    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BODY),
    });
    expect(res.status).toBe(403);
  });
});

// -------------------------------------------------------------------------
// Tests: Input validation
// -------------------------------------------------------------------------

describe("POST /credentials/issue-delegated — validation", () => {
  it("returns 400 for missing required fields", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });

  it("returns 400 for missing delegationId", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ ...VALID_BODY, delegationId: "" }),
    });
    expect(res.status).toBe(400);
  });

  it("returns 400 for empty credentialSubject", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ ...VALID_BODY, credentialSubject: {} }),
    });
    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid credentialSubject (schema validation)", async () => {
    const { app } = createTestApp();
    const token = await makeToken();
    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_BODY,
        credentialSubject: { name: "Jane Doe" },
      }),
    });
    expect(res.status).toBe(400);
  });
});

// -------------------------------------------------------------------------
// Tests: Delegation validation
// -------------------------------------------------------------------------

describe("POST /credentials/issue-delegated — delegation validation", () => {
  it("returns 403 for expired delegation", async () => {
    const { app } = createTestApp(makeExpiredDelegation());
    const token = await makeToken();
    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BODY),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("AUTHORIZATION_ERROR");
    expect(body.error.message).toContain("expired");
  });

  it("returns 403 for scope mismatch", async () => {
    const { app } = createTestApp(makeScopeMismatchDelegation());
    const token = await makeToken();
    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BODY),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as ErrorBody;
    expect(body.error.code).toBe("AUTHORIZATION_ERROR");
    expect(body.error.message).toContain("validation failed");
  });
});

// -------------------------------------------------------------------------
// Tests: Full delegated issuance round-trip
// -------------------------------------------------------------------------

describe("POST /credentials/issue-delegated — round-trip", () => {
  it("produces a valid VerifiableCredential with delegation reference", async () => {
    const { app } = createTestApp();
    const token = await makeToken();

    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BODY),
    });

    const body = await res.json();
    expect(res.status, `Expected 201 but got ${res.status}: ${JSON.stringify(body)}`).toBe(201);

    const { credential } = body as IssueDelegatedResponse;

    // VC structure
    expect(credential["@context"]).toContain("https://www.w3.org/ns/credentials/v2");
    expect(credential.type).toContain("VerifiableCredential");

    // Issuer comes from delegation's delegator
    expect(credential.issuer).toEqual({
      id: "https://university.example",
      name: "Example University",
    });

    // Credential subject
    expect(credential.credentialSubject.name).toBe("Jane Doe");
    expect(credential.credentialSubject.degree).toBe("Bachelor of Science");

    // Dates
    expect(credential.validFrom).toBe("2026-01-01T00:00:00Z");

    // Credential status
    expect(credential.credentialStatus).toBeDefined();
    expect(credential.credentialStatus!.type).toBe("DeDiRevocationListStatusV1");

    // Proof exists and is a Data Integrity proof
    expect(credential.proof).toBeDefined();
    expect(credential.proof.type).toBe("DataIntegrityProof");
    expect(credential.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(credential.proof.proofPurpose).toBe("assertionMethod");
    expect(credential.proof.proofValue).toBeDefined();
    expect(typeof credential.proof.proofValue).toBe("string");

    // verificationMethod references OpenCred's did:key
    expect(credential.proof.verificationMethod).toContain("did:key:");

    // Delegation certificate is embedded in the proof
    expect(credential.proof.delegationCertificate).toBeDefined();
    const delegationCert = credential.proof.delegationCertificate as Record<string, unknown>;
    expect(delegationCert.id).toBe("urn:uuid:delegation-1");
    expect((delegationCert.delegator as Record<string, unknown>).id).toBe("https://university.example");
  });

  it("includes validUntil when provided", async () => {
    const { app } = createTestApp();
    const token = await makeToken();

    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...VALID_BODY,
        validUntil: "2027-01-01T00:00:00Z",
      }),
    });

    expect(res.status).toBe(201);
    const { credential } = (await res.json()) as IssueDelegatedResponse;
    expect(credential.validUntil).toBe("2027-01-01T00:00:00Z");
  });

  it("uses delegator ID as issuer string when delegator has no name", async () => {
    const delegation = makeActiveDelegation({
      delegator: { id: "https://university.example" },
    });
    const { app } = createTestApp(delegation);
    const token = await makeToken();

    const res = await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BODY),
    });

    expect(res.status).toBe(201);
    const { credential } = (await res.json()) as IssueDelegatedResponse;
    expect(credential.issuer).toBe("https://university.example");
  });

  it("resolves delegation from DeDi with correct delegationId", async () => {
    const { app, dediClient } = createTestApp();
    const token = await makeToken();

    await app.request("/credentials/issue-delegated", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(VALID_BODY),
    });

    expect(dediClient.resolveDelegation).toHaveBeenCalledWith("urn:uuid:delegation-1");
  });
});
