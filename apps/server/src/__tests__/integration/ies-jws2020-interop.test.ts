/**
 * IES ElectricityCredential v1.2 × jws-2020 — the exact issuance shape the
 * external Energy Passport verifier integration consumes: hosted IES context
 * URL in @context (resolved from the bundled, @import-inlined snapshot) and
 * a JsonWebSignature2020 embedded proof with a detached RFC 7797 JWS.
 */
import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import type { Hono } from "hono";
import { createTestApp, generateTestKey, issueViaApp, verifyViaApp } from "./helpers.js";
import type { TestKeyPair } from "./helpers.js";
import { setActiveSigner } from "../../signing/key-manager.js";

const IES_CONTEXT =
  "https://india-energy-stack.github.io/ies-accelerator/schemas/ElectricityCredential/v1.2/context.jsonld";
const IES_INLINE_CONTEXT =
  "https://india-energy-stack.github.io/ies-accelerator/schemas/ElectricityCredential/v1.2/context.inline.jsonld";

let app: Hono;
let testKey: TestKeyPair;

beforeAll(() => {
  testKey = generateTestKey();
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
  setActiveSigner(testKey.signer);
});

const SUBJECT = {
  customerProfile: {
    customerNumber: "900000902588",
    idRef: { issuedBy: "did:web:issuer.example", subjectId: "ca:900000902588" },
    energyResources: [
      // `id` here maps to @id in the IES context — it must be an absolute
      // URI or RDF conversion drops it and strict canonicalization fails.
      { id: "urn:ies:meter:LSW002975", type: "METER", attributes: { meterCapability: "AMI" } },
    ],
  },
};

describe("IES electricity-credential v1.2 — jws-2020 issuance", () => {
  it("issues with the hosted IES context in @context and a detached-JWS proof, and verifies", async () => {
    const issuerDid = testKey.signer.id.split("#")[0];
    const res = await issueViaApp(app, {
      schemaId: "ies/electricity-credential/v1.2",
      issuerDid,
      credentialSubject: SUBJECT,
      validFrom: "2026-08-01T00:00:00Z",
      proofFormat: "jws-2020",
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as { credential: Record<string, unknown> };
    const cred = body.credential;
    // The flat inline context precedes v1.2 so DigiLocker (no `@import`
    // support) sees every field, while v1.2's definitions still win
    // (issue #764).
    expect(cred["@context"]).toEqual([
      "https://www.w3.org/ns/credentials/v2",
      IES_INLINE_CONTEXT,
      IES_CONTEXT,
      "https://w3id.org/security/suites/jws-2020/v1",
    ]);

    const proof = cred.proof as Record<string, unknown>;
    expect(proof.type).toBe("JsonWebSignature2020");
    expect(proof.jwt).toBeUndefined();
    expect((proof.jws as string).split(".")[1]).toBe(""); // detached payload

    const verifyRes = await verifyViaApp(app, cred);
    expect(verifyRes.status).toBe(200);
    const verdict = (await verifyRes.json()) as { valid: boolean; code: string };
    expect(verdict.code).toBe("VALID");
    expect(verdict.valid).toBe(true);
  });

  it("names the offending field when strict canonicalization rejects the payload (opencred-releases #13)", async () => {
    // A bare meter number as `energyResources[].id` is the shape that
    // produced the opaque "Failed to prepare JWS-2020 proof: Safe mode
    // validation error." report. The response must say which value is wrong.
    const issuerDid = testKey.signer.id.split("#")[0];
    const res = await issueViaApp(app, {
      schemaId: "ies/electricity-credential/v1.2",
      issuerDid,
      credentialSubject: {
        customerProfile: {
          customerNumber: "900000902588",
          energyResources: [
            { id: "LSW002975", type: "METER", attributes: { meterCapability: "AMI" } },
          ],
        },
      },
      validFrom: "2026-08-01T00:00:00Z",
      proofFormat: "jws-2020",
    });
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("CRYPTO_ERROR");
    expect(body.error.message).not.toContain("Safe mode validation error");
    expect(body.error.message).toContain('identifier "LSW002975"');
    expect(body.error.message).toContain("is not an absolute URI");
  });

  it("names an undefined credentialSubject property under strict canonicalization", async () => {
    const issuerDid = testKey.signer.id.split("#")[0];
    const res = await issueViaApp(app, {
      schemaId: "ies/electricity-credential/v1.2",
      issuerDid,
      credentialSubject: {
        customerProfile: {
          customerNumber: "900000902588",
          energyResources: [{ id: "urn:ies:meter:LSW002975", type: "METER" }],
          mobileNumber: "9594673877",
        },
      },
      validFrom: "2026-08-01T00:00:00Z",
      proofFormat: "jws-2020",
    });
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: { code: string; message: string } };
    expect(body.error.message).toContain('property "mobileNumber" is not defined');
  });

  it("issues with data-integrity too (same canonicalization path)", async () => {
    const issuerDid = testKey.signer.id.split("#")[0];
    const res = await issueViaApp(app, {
      schemaId: "ies/electricity-credential/v1.2",
      issuerDid,
      credentialSubject: SUBJECT,
      validFrom: "2026-08-01T00:00:00Z",
      proofFormat: "data-integrity",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { credential: Record<string, unknown> };
    const context = body.credential["@context"] as string[];
    expect(context.indexOf(IES_INLINE_CONTEXT)).toBeGreaterThan(-1);
    expect(context.indexOf(IES_INLINE_CONTEXT)).toBeLessThan(context.indexOf(IES_CONTEXT));
    const verifyRes = await verifyViaApp(app, body.credential);
    const verdict = (await verifyRes.json()) as { valid: boolean };
    expect(verdict.valid).toBe(true);
  });
});
