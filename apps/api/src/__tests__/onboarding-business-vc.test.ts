import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import { jwtVerify } from "jose";
import {
  createBusinessVcOnboardingRoutes,
  type BusinessVcOnboardingDeps,
} from "../routes/onboarding.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

// --- Mock verifyCredential ---
// We mock the verification module so we can control whether a VC passes or fails
// without needing real cryptographic proofs.
vi.mock("@opencred/verification", async () => {
  const actual = await vi.importActual<typeof import("@opencred/verification")>(
    "@opencred/verification",
  );
  return {
    ...actual,
    verifyCredential: vi.fn(),
  };
});

// --- Mock registerDelegation ---
vi.mock("@opencred/delegation", async () => {
  const actual = await vi.importActual<typeof import("@opencred/delegation")>(
    "@opencred/delegation",
  );
  return {
    ...actual,
    registerDelegation: vi.fn().mockResolvedValue({
      id: "urn:uuid:mock-delegation-id",
      issuerDid: "did:example:delegator",
      delegateDid: "did:key:z6Mk-opencred",
      scope: [],
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 3600_000).toISOString(),
      certificate: {},
    }),
  };
});

import { verifyCredential } from "@opencred/verification";
import { registerDelegation } from "@opencred/delegation";

const mockedVerify = vi.mocked(verifyCredential);
const mockedRegister = vi.mocked(registerDelegation);

const logger = makeTestLogger();

// --- Test constants ---

const TEST_JWT_SECRET = "test-jwt-secret-must-be-at-least-32-characters-long";
const TEST_JWT_ISSUER = "opencred-test";
const TEST_JWT_EXPIRY = 3600;
const TEST_JWT_KEY = new TextEncoder().encode(TEST_JWT_SECRET);
const TEST_OPENCRED_DID = "did:key:z6MktestedOpencredKey123456";

// --- Response types ---

interface BusinessVcResponseBody {
  namespace: string;
  capabilityToken: string;
  issuerIdentifier: string;
  expiresAt: string;
  delegationId?: string;
}

interface ErrorBody {
  error: { code: string; message: string };
}

// --- Test fixtures ---

function makeDataIntegrityVC(overrides: Record<string, unknown> = {}) {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential", "BusinessRegistrationCredential"],
    issuer: "did:example:authority",
    credentialSubject: {
      id: "did:example:acme-corp",
      name: "Acme Corporation",
      legalName: "Acme Corp Ltd.",
      ...overrides,
    },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-rdfc-2022",
      verificationMethod: "did:example:authority#key-1",
      proofPurpose: "assertionMethod",
      created: "2025-01-01T00:00:00Z",
      proofValue: "z3FXQjecWfPkMaoXH3NW5XcYsm...",
    },
  };
}

function makeVcJwt(credentialSubject: Record<string, unknown> = {}) {
  const header = { alg: "ES256", typ: "JWT" };
  const payload = {
    iss: "did:example:authority",
    sub: "did:example:acme-corp",
    nbf: Math.floor(Date.now() / 1000) - 3600,
    exp: Math.floor(Date.now() / 1000) + 86400,
    vc: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", "BusinessRegistrationCredential"],
      credentialSubject: {
        id: "did:example:acme-corp",
        name: "Acme Corporation",
        ...credentialSubject,
      },
    },
  };
  const sig = "fake-signature-for-testing";
  return [
    Buffer.from(JSON.stringify(header)).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    Buffer.from(sig).toString("base64url"),
  ].join(".");
}

function makeSdJwtVc() {
  const header = { alg: "ES256", typ: "sd+jwt" };
  const payload = {
    iss: "did:example:authority",
    sub: "did:example:acme-corp",
    nbf: Math.floor(Date.now() / 1000) - 3600,
    exp: Math.floor(Date.now() / 1000) + 86400,
    vct: "BusinessRegistrationCredential",
    credentialSubject: {
      id: "did:example:acme-corp",
      name: "Acme Corporation",
    },
  };
  const issuerJwt = [
    Buffer.from(JSON.stringify(header)).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    Buffer.from("fake-sig").toString("base64url"),
  ].join(".");
  // SD-JWT VC format: issuerJwt~disclosure1~disclosure2~
  return `${issuerJwt}~`;
}

// --- Test app factory ---

function createTestApp(overrides: Partial<BusinessVcOnboardingDeps> = {}) {
  const app = new Hono();
  app.route(
    "/onboarding",
    createBusinessVcOnboardingRoutes({
      jwtSigningKey: overrides.jwtSigningKey ?? TEST_JWT_KEY,
      jwtIssuer: overrides.jwtIssuer ?? TEST_JWT_ISSUER,
      jwtExpirySeconds: overrides.jwtExpirySeconds ?? TEST_JWT_EXPIRY,
      verifierConfig: overrides.verifierConfig,
      dediClient: overrides.dediClient,
      opencredSigningKeyDid: overrides.opencredSigningKeyDid ?? TEST_OPENCRED_DID,
    }),
  );
  app.onError(errorHandler(logger));
  return app;
}

function postBusinessVc(app: Hono, body: unknown) {
  return app.request("/onboarding/business-vc", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// --- Tests ---

describe("POST /onboarding/business-vc", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: verification passes
    mockedVerify.mockResolvedValue({
      code: "VALID",
      verified: true,
      checks: [{ name: "signature", passed: true }],
    });
  });

  describe("input validation", () => {
    it("returns 400 for empty body", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {});
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 for missing businessCredential", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        signingPreference: "delegated",
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
    });

    it("returns 400 when signingPreference is interface and publicKey is missing", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "interface",
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VALIDATION_ERROR");
      expect(body.error.message).toContain("publicKey");
    });
  });

  describe("valid Data Integrity business VC — interface signing", () => {
    it("returns 201 with namespace, capabilityToken, issuerIdentifier, and expiresAt", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "interface",
        publicKey: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      expect(body.namespace).toBeDefined();
      expect(body.capabilityToken).toBeDefined();
      expect(body.capabilityToken.split(".")).toHaveLength(3);
      expect(body.issuerIdentifier).toBeDefined();
      expect(body.expiresAt).toBeDefined();
      expect(new Date(body.expiresAt).getTime()).toBeGreaterThan(Date.now());
    });

    it("issues token with credentials:build and credentials:revoke scopes", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "interface",
        publicKey: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      const { payload } = await jwtVerify(body.capabilityToken, TEST_JWT_KEY, {
        issuer: TEST_JWT_ISSUER,
      });
      expect(payload.scope).toEqual(["credentials:build", "credentials:revoke"]);
    });

    it("does not return a delegationId", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "interface",
        publicKey: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      expect(body.delegationId).toBeUndefined();
    });
  });

  describe("valid VC-JWT business VC", () => {
    it("returns 201 with correct response", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeVcJwt(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      expect(body.namespace).toMatch(/^urn:opencred:issuer:business:/);
      expect(body.capabilityToken).toBeDefined();
      expect(body.issuerIdentifier).toBeDefined();
    });
  });

  describe("valid SD-JWT VC business VC", () => {
    it("returns 201 with correct response", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeSdJwtVc(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      expect(body.namespace).toMatch(/^urn:opencred:issuer:business:/);
      expect(body.capabilityToken).toBeDefined();
    });
  });

  describe("invalid business VC — rejection", () => {
    it("returns 400 when business VC has bad signature", async () => {
      mockedVerify.mockResolvedValue({
        code: "INVALID",
        verified: false,
        checks: [{ name: "signature", passed: false, detail: "Signature mismatch" }],
      });
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
      expect(body.error.message).toContain("verification failed");
    });

    it("returns 400 when business VC is expired", async () => {
      mockedVerify.mockResolvedValue({
        code: "EXPIRED",
        verified: false,
        checks: [
          { name: "signature", passed: true },
          { name: "dates", passed: false, detail: "Credential has expired" },
        ],
      });
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      expect(body.error.code).toBe("VERIFICATION_ERROR");
      expect(body.error.message).toContain("expired");
    });
  });

  describe("delegated signing preference", () => {
    it("returns 201 with delegationId when delegated", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      expect(body.delegationId).toBeDefined();
      expect(body.delegationId).toMatch(/^urn:uuid:/);
    });

    it("issues token with credentials:issue-delegated and credentials:revoke scopes", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      const { payload } = await jwtVerify(body.capabilityToken, TEST_JWT_KEY, {
        issuer: TEST_JWT_ISSUER,
      });
      expect(payload.scope).toEqual(["credentials:issue-delegated", "credentials:revoke"]);
    });

    it("registers delegation via registerDelegation with the provided dediClient", async () => {
      const mockDediClient = {
        registerDelegation: vi.fn().mockResolvedValue({
          id: "urn:uuid:registered",
          issuerDid: "did:example:acme-corp",
          delegateDid: TEST_OPENCRED_DID,
          scope: [],
          validFrom: new Date().toISOString(),
          validUntil: new Date(Date.now() + 3600_000).toISOString(),
          certificate: {},
        }),
      } as any;

      const app = createTestApp({ dediClient: mockDediClient });
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);

      // BLOCKER 3 fix: Assert that the mocked registerDelegation (from
      // @opencred/delegation) was called with the provided dediClient as the
      // first argument, confirming the client is properly threaded through.
      expect(mockedRegister).toHaveBeenCalledTimes(1);
      expect(mockedRegister).toHaveBeenCalledWith(
        mockDediClient,
        expect.objectContaining({
          certificate: expect.objectContaining({
            type: ["DelegationCertificate"],
            proof: expect.objectContaining({
              type: "BusinessCredentialAuthorisation",
            }),
          }),
        }),
      );
    });

    it("does not call registerDelegation when dediClient is not provided", async () => {
      const app = createTestApp({ dediClient: undefined });
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      expect(mockedRegister).not.toHaveBeenCalled();
    });
  });

  describe("namespace format", () => {
    it("generates namespace with urn:opencred:issuer:business: prefix", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      expect(body.namespace).toBe("urn:opencred:issuer:business:acme-corporation");
    });

    it("generates same namespace for same org name", async () => {
      const app = createTestApp();
      const res1 = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      const body1 = (await res1.json()) as BusinessVcResponseBody;

      const res2 = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      const body2 = (await res2.json()) as BusinessVcResponseBody;

      expect(body1.namespace).toBe(body2.namespace);
    });

    it("uses legalName when name is absent", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC({ name: undefined }),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      expect(body.namespace).toBe("urn:opencred:issuer:business:acme-corp-ltd");
    });
  });

  describe("DeDi namespace registration gap", () => {
    it("succeeds even without namespace registration (documents the gap)", async () => {
      // The DeDi client does not yet have a createNamespace() method.
      // This test documents that onboarding works without namespace registration
      // and that the namespace is computed deterministically.
      const mockDediClient = {
        registerDelegation: vi.fn().mockResolvedValue({
          id: "urn:uuid:registered",
          issuerDid: "did:example:acme-corp",
          delegateDid: TEST_OPENCRED_DID,
          scope: [],
          validFrom: new Date().toISOString(),
          validUntil: new Date(Date.now() + 3600_000).toISOString(),
          certificate: {},
        }),
      } as any;

      const app = createTestApp({ dediClient: mockDediClient });
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      // Namespace is computed but not registered in DeDi as a first-class entity
      expect(body.namespace).toBe("urn:opencred:issuer:business:acme-corporation");

      // Verify that delegation registration still goes through DeDi
      expect(mockedRegister).toHaveBeenCalledTimes(1);
    });
  });

  describe("default signing preference", () => {
    it("defaults to interface when signingPreference is omitted (requires publicKey)", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        publicKey: { kty: "EC", crv: "P-256", x: "abc", y: "def" },
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      const { payload } = await jwtVerify(body.capabilityToken, TEST_JWT_KEY, {
        issuer: TEST_JWT_ISSUER,
      });
      expect(payload.scope).toEqual(["credentials:build", "credentials:revoke"]);
      expect(body.delegationId).toBeUndefined();
    });
  });

  describe("error responses do not leak secrets", () => {
    it("does not include stack traces or internal paths", async () => {
      mockedVerify.mockResolvedValue({
        code: "INVALID",
        verified: false,
        checks: [{ name: "signature", passed: false, detail: "Signature mismatch" }],
      });
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrorBody;
      const bodyStr = JSON.stringify(body);
      expect(bodyStr).not.toContain("/Users/");
      expect(bodyStr).not.toContain("node_modules");
      expect(bodyStr).not.toContain("stack");
    });
  });

  describe("no auth required", () => {
    it("responds without Authorization header", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(403);
      expect(res.status).toBe(201);
    });
  });

  describe("capability token properties", () => {
    it("token is verifiable with the signing key", async () => {
      const app = createTestApp();
      const res = await postBusinessVc(app, {
        businessCredential: makeDataIntegrityVC(),
        signingPreference: "delegated",
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as BusinessVcResponseBody;
      const { payload } = await jwtVerify(body.capabilityToken, TEST_JWT_KEY, {
        issuer: TEST_JWT_ISSUER,
      });
      expect(payload.iss).toBe(TEST_JWT_ISSUER);
      expect(payload.sub).toMatch(/^business-vc:/);
      expect(payload.namespace).toBe(body.namespace);
    });
  });
});
