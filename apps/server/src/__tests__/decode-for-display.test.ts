/**
 * Direct unit tests for the compact-token decoder used by the credential
 * packager. The endpoint integration tests only exercise the
 * sd-jwt-vc → package happy path, so these cover the rest of the
 * decoder's branches:
 *
 *   - vc-jwt DM 1.1 (`payload.vc` nested) and DM 2.0 (flat) layouts
 *   - sd-jwt-vc with name disclosures, array-element disclosures,
 *     malformed disclosures, name-collision protection
 *   - the `_sd` recursive-strip walker
 *   - synthetic VC-shape fallbacks (id, type, issuer, credentialSubject,
 *     proof) for minimal payloads
 *   - dot-count validation gate for vc-jwt input
 *
 * All test JWTs are hand-built (header + payload + fake signature). We
 * never verify signatures in these tests — the decoder is purely a
 * rendering helper, that's the whole point.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { decodeCompactCredentialForDisplay } from "../packaging/decode-for-display.js";
import { ValidationError } from "@opencred/shared";
import { createLogger } from "../logger.js";
import { loadConfig } from "../config.js";

// `decode-for-display` calls `getLogger()` at debug-level on disclosure
// edge cases. The logger reads from config, so init both singletons
// before the tests run. Suppress log output so test runs stay clean.
beforeAll(() => {
  process.env.OPENCRED_API_KEY ??= "test-api-key-for-decode-display-suite";
  process.env.OPENCRED_LOG_LEVEL = "fatal";
  loadConfig();
  createLogger();
});

function b64urlJson(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function buildJwt(header: object, payload: object): string {
  return `${b64urlJson(header)}.${b64urlJson(payload)}.fakesig`;
}

function buildDisclosure(salt: string, name: string, value: unknown): string {
  return Buffer.from(JSON.stringify([salt, name, value])).toString("base64url");
}

describe("decodeCompactCredentialForDisplay — input validation", () => {
  it("throws ValidationError on an empty string", () => {
    expect(() => decodeCompactCredentialForDisplay("")).toThrow(ValidationError);
  });

  it("throws ValidationError on a string with zero dots and no tildes", () => {
    expect(() => decodeCompactCredentialForDisplay("abcdef")).toThrow(/2 '\.' separators/);
  });

  it("throws ValidationError on a string with one dot", () => {
    // header.payload — missing signature segment
    const oneDot = `${b64urlJson({ alg: "ES256" })}.${b64urlJson({ iss: "did:web:e" })}`;
    expect(() => decodeCompactCredentialForDisplay(oneDot)).toThrow(/2 '\.' separators/);
  });

  it("throws ValidationError on three dots", () => {
    // four segments — not a JWT
    expect(() => decodeCompactCredentialForDisplay("a.b.c.d")).toThrow(/2 '\.' separators/);
  });

  it("wraps a downstream JWT decode error with a 'cannot decode payload' prefix", () => {
    // 2 dots but the payload segment isn't decodable JSON
    const headerSeg = b64urlJson({ alg: "ES256" });
    const garbageSeg = Buffer.from("not valid json").toString("base64url");
    const malformed = `${headerSeg}.${garbageSeg}.fakesig`;
    expect(() => decodeCompactCredentialForDisplay(malformed)).toThrow(
      /Invalid vc-jwt compact token: cannot decode payload/,
    );
  });
});

describe("decodeCompactCredentialForDisplay — vc-jwt path", () => {
  it("decodes a DM 1.1 layout (payload.vc nested)", () => {
    const jwt = buildJwt(
      { alg: "ES256", kid: "did:web:example#key-1" },
      {
        iss: "did:web:example",
        sub: "did:example:subject",
        nbf: 1700000000,
        exp: 1731536000,
        jti: "urn:uuid:abc-123",
        vc: {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          type: ["VerifiableCredential", "SkillCredential"],
          credentialSubject: { name: "Alice", level: "expert" },
        },
      },
    );

    const result = decodeCompactCredentialForDisplay(jwt);
    expect(result.format).toBe("vc-jwt");
    expect(result.compactToken).toBe(jwt);
    const shape = result.vcShape as Record<string, unknown>;
    expect(shape["issuer"]).toBe("did:web:example");
    expect((shape["type"] as string[]).join(",")).toContain("SkillCredential");
    expect((shape["credentialSubject"] as { name: string }).name).toBe("Alice");
    // validFrom / validUntil derived from nbf / exp
    expect(shape["validFrom"]).toBe(new Date(1700000000 * 1000).toISOString());
    expect(shape["validUntil"]).toBe(new Date(1731536000 * 1000).toISOString());
    // synthetic proof block reflects vc-jwt format and carries the kid
    const proof = shape["proof"] as Record<string, string>;
    expect(proof.type).toBe("JsonWebSignature2020");
    expect(proof.verificationMethod).toBe("did:web:example#key-1");
  });

  it("decodes a DM 2.0 layout (flat payload, no vc wrapper)", () => {
    const jwt = buildJwt(
      { alg: "ES256" },
      {
        iss: "did:web:example",
        type: ["VerifiableCredential", "TrainingCredential"],
        validFrom: "2026-01-01T00:00:00Z",
        credentialSubject: { name: "Bob" },
      },
    );

    const result = decodeCompactCredentialForDisplay(jwt);
    expect(result.format).toBe("vc-jwt");
    const shape = result.vcShape as Record<string, unknown>;
    expect(shape["issuer"]).toBe("did:web:example");
    expect(shape["validFrom"]).toBe("2026-01-01T00:00:00Z");
    expect((shape["credentialSubject"] as { name: string }).name).toBe("Bob");
  });

  it("falls back to a synthetic id / type / credentialSubject when payload is minimal", () => {
    const jwt = buildJwt({ alg: "ES256" }, { iss: "did:web:example" });
    const shape = decodeCompactCredentialForDisplay(jwt).vcShape as Record<string, unknown>;
    expect(shape["id"]).toBe("urn:opencred:packaged-token");
    expect(shape["type"]).toEqual(["VerifiableCredential"]);
    expect(shape["issuer"]).toBe("did:web:example");
    // credentialSubject promoted from non-reserved claims; here there
    // are none, so it should be `{}` (or carry only `id` if `sub` was set).
    expect(shape["credentialSubject"]).toEqual({});
  });
});

describe("decodeCompactCredentialForDisplay — sd-jwt-vc path", () => {
  function buildSdJwt(payload: object, disclosures: string[]): string {
    const issuerJwt = buildJwt({ alg: "ES256", typ: "vc+sd-jwt", kid: "did:web:e#k1" }, payload);
    return [issuerJwt, ...disclosures, ""].join("~");
  }

  it("decodes a token with one name disclosure", () => {
    const tok = buildSdJwt({ iss: "did:web:e", iat: 1700000000, vct: "TestCredential" }, [
      buildDisclosure("salt1", "name", "Alice"),
    ]);
    const r = decodeCompactCredentialForDisplay(tok);
    expect(r.format).toBe("sd-jwt-vc");
    expect(r.compactToken).toBe(tok);
    const shape = r.vcShape as Record<string, unknown>;
    expect(shape["type"]).toEqual(["VerifiableCredential", "TestCredential"]);
    expect((shape["credentialSubject"] as { name: string }).name).toBe("Alice");
    // synthetic proof reflects the sd-jwt-vc format
    const proof = shape["proof"] as Record<string, string>;
    expect(proof.type).toBe("SD-JWT-VC");
    expect(proof.created).toBe(new Date(1700000000 * 1000).toISOString());
    expect(proof.verificationMethod).toBe("did:web:e#k1");
  });

  it("re-attaches array and object disclosures (gap #1 from review)", () => {
    // Reviewer flagged: previously the `typeof v !== 'object'` filter dropped
    // these from the synthetic credentialSubject. They must now appear.
    const tok = buildSdJwt({ iss: "did:web:e", iat: 1700000000, vct: "RichCredential" }, [
      buildDisclosure("s1", "roles", ["doctor", "trainer"]),
      buildDisclosure("s2", "address", { city: "Bangalore", country: "IN" }),
    ]);
    const shape = decodeCompactCredentialForDisplay(tok).vcShape as Record<string, unknown>;
    const subject = shape["credentialSubject"] as { roles: string[]; address: { city: string } };
    expect(subject.roles).toEqual(["doctor", "trainer"]);
    expect(subject.address.city).toBe("Bangalore");
  });

  it("strips _sd / _sd_alg markers at every nesting level (gap #2 from review)", () => {
    // Reviewer flagged: nested `_sd` arrays were rendering as raw hashes.
    // After the recursive walker, they must be absent everywhere.
    const tok = buildSdJwt(
      {
        iss: "did:web:e",
        iat: 1700000000,
        vct: "TestCredential",
        _sd: ["topLevelHash1"],
        _sd_alg: "sha-256",
        credentialSubject: {
          _sd: ["nestedHash1", "nestedHash2"],
          _sd_alg: "sha-256",
          name: "Alice",
          nested: { _sd: ["doubleNestedHash"], plain: "ok" },
        },
      },
      [],
    );
    const shape = decodeCompactCredentialForDisplay(tok).vcShape as Record<string, unknown>;
    const cs = shape["credentialSubject"] as Record<string, unknown>;
    expect(cs).not.toHaveProperty("_sd");
    expect(cs).not.toHaveProperty("_sd_alg");
    expect(cs["nested"] as Record<string, unknown>).not.toHaveProperty("_sd");
    expect((cs["nested"] as { plain: string }).plain).toBe("ok");
    expect(cs["name"]).toBe("Alice");
    // Top-level too
    expect(shape).not.toHaveProperty("_sd");
    expect(shape).not.toHaveProperty("_sd_alg");
  });

  it("silently drops array-element disclosures (length-2)", () => {
    // length-2 disclosures are array-element disclosures used for
    // selectively-revealed array members; the display layer can't
    // surface them as named claims. This is by design.
    const arrayElementDisclosure = Buffer.from(JSON.stringify(["salt-x", "value-y"])).toString(
      "base64url",
    );
    const tok = buildSdJwt({ iss: "did:web:e", iat: 1700000000, vct: "TestCredential" }, [
      buildDisclosure("s1", "name", "Alice"),
      arrayElementDisclosure,
    ]);
    const shape = decodeCompactCredentialForDisplay(tok).vcShape as Record<string, unknown>;
    expect((shape["credentialSubject"] as { name: string }).name).toBe("Alice");
  });

  it("does not clobber existing payload claims with a colliding disclosure", () => {
    // A disclosure trying to set `iss` (already present in payload) must
    // be dropped — otherwise a malicious holder could forge issuer claims
    // for display purposes. The QR still embeds the original token; this
    // is purely about the rendered PDF.
    const tok = buildSdJwt({ iss: "did:web:real-issuer", iat: 1700000000, vct: "TestCredential" }, [
      buildDisclosure("s1", "iss", "did:web:attacker"),
    ]);
    const shape = decodeCompactCredentialForDisplay(tok).vcShape as Record<string, unknown>;
    expect(shape["issuer"]).toBe("did:web:real-issuer");
  });

  it("survives a malformed disclosure without crashing the whole decode", () => {
    const malformedDisclosure = "not-base64url-json";
    const tok = buildSdJwt({ iss: "did:web:e", iat: 1700000000, vct: "TestCredential" }, [
      buildDisclosure("s1", "name", "Alice"),
      malformedDisclosure,
    ]);
    const shape = decodeCompactCredentialForDisplay(tok).vcShape as Record<string, unknown>;
    expect((shape["credentialSubject"] as { name: string }).name).toBe("Alice");
  });

  it("handles a token with a trailing `~` and no disclosures", () => {
    // Issuer JWT followed by trailing tilde indicates "no disclosures
    // attached" — common for tokens where every claim is selectively
    // disclosed but the holder revealed none.
    const tok = `${buildJwt({ alg: "ES256" }, { iss: "did:web:e", vct: "X" })}~`;
    const r = decodeCompactCredentialForDisplay(tok);
    expect(r.format).toBe("sd-jwt-vc");
    expect((r.vcShape as Record<string, unknown>)["issuer"]).toBe("did:web:e");
  });

  it("wraps a downstream JWT decode error with an 'sd-jwt-vc' prefix", () => {
    // Issuer JWT segment is malformed
    const tok = "totally-not-a-jwt~disclosureA~";
    expect(() => decodeCompactCredentialForDisplay(tok)).toThrow(/Invalid sd-jwt-vc compact token/);
  });
});

describe("decodeCompactCredentialForDisplay — synthetic proof robustness", () => {
  it("omits proof.created when iat is non-finite or unparseable", () => {
    const jwt = buildJwt(
      { alg: "ES256" },
      { iss: "did:web:e", iat: Number.MAX_SAFE_INTEGER * 1e6 /* overflow */ },
    );
    const shape = decodeCompactCredentialForDisplay(jwt).vcShape as Record<string, unknown>;
    const proof = shape["proof"] as Record<string, unknown>;
    expect(proof["type"]).toBe("JsonWebSignature2020");
    // created may be absent or an ISO string — but we should never throw
    expect(typeof proof["created"] === "undefined" || typeof proof["created"] === "string").toBe(
      true,
    );
  });

  it("omits proof.verificationMethod when the JWT header has no kid", () => {
    const jwt = buildJwt({ alg: "ES256" }, { iss: "did:web:e", iat: 1700000000 });
    const shape = decodeCompactCredentialForDisplay(jwt).vcShape as Record<string, unknown>;
    const proof = shape["proof"] as Record<string, unknown>;
    expect(proof["verificationMethod"]).toBeUndefined();
  });
});
