/**
 * Regression test for issue #632 — the JWT `kid` protected-header on every
 * issued credential must match the configured issuer DID method.
 *
 * Before the key-manager override landed, `OPENCRED_ISSUER_DID_METHOD=web`
 * left `signer.id` as the key-derived `did:key:…` value, so credentials
 * were signed with `kid = did:key:…` even though the credential's `issuer`
 * field correctly carried `did:web:<domain>`. Verifiers resolved the
 * did:web document, found `verificationMethod[0].id = did:web:…#key-0`,
 * and failed kid-matching → `UNRESOLVABLE`.
 *
 * This test wires a real Hono app with a fake signer whose `id` and
 * `metadata.id` are already overridden (mirroring what `loadSigningKey`
 * does at boot for method=web), issues a credential through
 * `POST /credentials/issue`, decodes the JWT protected header, and
 * asserts the `kid` matches.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { generateKeyPairSync, sign as ecSign, type KeyObject } from "node:crypto";
import { computeFingerprint } from "@opencred/signing";
import type { Signer, SignerMetadata } from "@opencred/signing";
import { createTestApp, VALID_ISSUE_REQUEST } from "./helpers.js";
import { setActiveSigner } from "../signing/key-manager.js";
import type { Hono } from "hono";

/**
 * Build a fake Signer whose verification-method id is the supplied override
 * (e.g. `did:web:issuer.example.org#key-0`). Algorithm is P-256; sign()
 * uses raw r||s encoding to match what software-signer produces.
 */
function makeOverriddenSigner(id: string): {
  signer: Signer;
  privateKey: KeyObject;
  publicKey: KeyObject;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const fingerprint = computeFingerprint(publicKey);
  const metadata: SignerMetadata = {
    id,
    algorithm: "P-256",
    type: "software",
    fingerprint,
    label: "kid-test",
  };
  const signer: Signer = {
    id,
    algorithm: "P-256",
    type: "software",
    metadata,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      const sig = ecSign(null, Buffer.from(data), {
        key: privateKey,
        dsaEncoding: "ieee-p1363",
      });
      return new Uint8Array(sig);
    },
  };
  return { signer, privateKey, publicKey };
}

function decodeJwtHeader(jwt: string): Record<string, unknown> {
  const headerB64 = jwt.split(".")[0]!;
  const headerJson = Buffer.from(headerB64, "base64url").toString("utf-8");
  return JSON.parse(headerJson) as Record<string, unknown>;
}

let app: Hono;

beforeAll(() => {
  // Each test re-creates the app via beforeEach below; nothing to do here.
});

beforeEach(() => {
  app = createTestApp({ devModeNoAuth: true });
});

describe("POST /credentials/issue — JWT kid header tracks signer.id (#632)", () => {
  it("emits kid=did:web:<domain>#key-0 when signer.id is a did:web URL", async () => {
    const did = "did:web:issuer.example.org";
    const expectedKid = `${did}#key-0`;
    const { signer } = makeOverriddenSigner(expectedKid);
    setActiveSigner(signer);

    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        // Honour the configured issuer DID; without this, the resolver in
        // routes/credentials.ts substitutes the default test-issuer DID and
        // we lose the value of the assertion.
        issuerDid: did,
      }),
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as { credential: { proof: { jwt: string }; issuer: string } };
    expect(body.credential.issuer).toBe(did);

    const header = decodeJwtHeader(body.credential.proof.jwt);
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBe(expectedKid);
    // Crucially, kid must NOT carry the underlying did:key bytes — that
    // was the user-reported bug.
    expect((header.kid as string).startsWith("did:key:")).toBe(false);
  });

  it("emits kid=did:key:... when signer.id is a did:key URL (method=key)", async () => {
    // Sanity: did:key issuers continue to work unchanged. The override is a
    // no-op for them.
    const didKey = "did:key:z6MkSentinelTestKey";
    const expectedKid = `${didKey}#z6MkSentinelTestKey`;
    const { signer } = makeOverriddenSigner(expectedKid);
    setActiveSigner(signer);

    const res = await app.request("/credentials/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...VALID_ISSUE_REQUEST,
        issuerDid: didKey,
      }),
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as { credential: { proof: { jwt: string } } };
    const header = decodeJwtHeader(body.credential.proof.jwt);
    expect(header.kid).toBe(expectedKid);
  });
});
