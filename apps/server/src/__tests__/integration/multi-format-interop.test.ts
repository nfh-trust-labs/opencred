import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import type { Hono } from "hono";
import {
  createTestApp,
  generateTestKey,
  FUNCTIONAL_IDENTITY_SUBJECT,
  issueViaApp,
  verifyViaApp,
} from "./helpers.js";
import type { TestKeyPair } from "./helpers.js";
import { setActiveSigner } from "../../signing/key-manager.js";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
});

const PROOF_FORMATS = ["data-integrity", "vc-jwt", "sd-jwt-vc"] as const;

describe("multi-format interop — same subject, 3 proof formats, all verify", () => {
  for (const proofFormat of PROOF_FORMATS) {
    it(`issue + verify round-trip: ${proofFormat}`, async () => {
      const issuerDid = testKey.signer.id.split("#")[0];
      const issueBody: Record<string, unknown> = {
        schemaId: "functional-identity/v1",
        issuerDid,
        credentialSubject: FUNCTIONAL_IDENTITY_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat,
      };

      if (proofFormat === "sd-jwt-vc") {
        issueBody["selectiveDisclosureClaims"] = ["name"];
      }

      const issueRes = await issueViaApp(app, issueBody);
      expect(issueRes.status).toBe(200);

      const issued = (await issueRes.json()) as {
        credential: unknown;
        proofFormat: string;
        isCompactToken: boolean;
      };
      expect(issued.proofFormat).toBe(proofFormat);

      // For vc-jwt the issue response wraps the JWT in a JSON envelope with
      // proof.jwt. The verify endpoint expects the compact JWT string for JWT
      // formats, not the JSON envelope.
      let verifyInput: unknown;
      if (proofFormat === "vc-jwt") {
        const cred = issued.credential as Record<string, unknown>;
        const proof = cred.proof as Record<string, unknown>;
        verifyInput = proof.jwt as string;
      } else {
        verifyInput = issued.credential;
      }

      const verifyRes = await verifyViaApp(app, verifyInput);
      expect(verifyRes.status).toBe(200);

      const verifyResult = (await verifyRes.json()) as { valid: boolean; code: string };
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.code).toBe("VALID");
    });
  }

  it("all 3 formats produce structurally distinct outputs", async () => {
    const issuerDid = testKey.signer.id.split("#")[0];
    const results: Map<string, unknown> = new Map();

    for (const proofFormat of PROOF_FORMATS) {
      const issueBody: Record<string, unknown> = {
        schemaId: "functional-identity/v1",
        issuerDid,
        credentialSubject: FUNCTIONAL_IDENTITY_SUBJECT,
        validFrom: "2025-06-15T00:00:00Z",
        proofFormat,
      };
      if (proofFormat === "sd-jwt-vc") {
        issueBody["selectiveDisclosureClaims"] = ["name"];
      }

      const res = await issueViaApp(app, issueBody);
      const body = (await res.json()) as { credential: unknown; isCompactToken: boolean };
      results.set(proofFormat, body);
    }

    const di = results.get("data-integrity") as { credential: Record<string, unknown>; isCompactToken: boolean };
    expect(di.isCompactToken).toBe(false);
    expect(typeof di.credential).toBe("object");
    expect((di.credential as Record<string, unknown>).proof).toBeDefined();

    const vcJwt = results.get("vc-jwt") as { credential: Record<string, unknown>; isCompactToken: boolean };
    expect(vcJwt.isCompactToken).toBe(false);
    expect(typeof vcJwt.credential).toBe("object");
    const vcJwtProof = (vcJwt.credential as Record<string, unknown>).proof as Record<string, unknown>;
    expect(vcJwtProof.jwt).toBeDefined();

    const sdJwt = results.get("sd-jwt-vc") as { credential: string; isCompactToken: boolean };
    expect(sdJwt.isCompactToken).toBe(true);
    expect(typeof sdJwt.credential).toBe("string");
    expect(sdJwt.credential).toContain("~");
  });
});
