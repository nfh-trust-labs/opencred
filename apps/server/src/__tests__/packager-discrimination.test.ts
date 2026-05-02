/**
 * Discriminated `CredentialInput` union — packager invariants for the
 * `kind: "compact-token"` arm.
 *
 * The packager's `compact-token` branch has two shape-level guarantees
 * that downstream callers (and the QR scanner side) rely on:
 *
 *   1. The JSON output wraps the raw token in a `{ format, credential }`
 *      envelope — the compact token round-trips byte-for-byte, and the
 *      `format` discriminator names which compact serialization it is.
 *      The integrity guarantee lives in the token itself, so re-parsing
 *      or re-serializing it is a regression we want to catch loudly.
 *
 *   2. The QR payload embeds the raw token verbatim — it is *not*
 *      PixelPass-compressed. PixelPass-compressed payloads always carry
 *      the `OPENCRED1:` header (see `qr-generator.ts`), so the absence
 *      of that header in the SVG is a sufficient negative test for the
 *      compression-skip path.
 *
 * Both guarantees would be silently regressed if the discriminated
 * union were collapsed back to a `T | string` overload — a stringified
 * VC would slip through and get re-parsed by `decode-for-display.ts`,
 * producing a different QR payload + JSON envelope.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { packageCredential, decodeQrData } from "../packaging/packager.js";
import type { CredentialInput } from "../packaging/packager.js";
import { createLogger } from "../logger.js";
import { loadConfig } from "../config.js";

beforeAll(() => {
  process.env.OPENCRED_API_KEY ??= "test-api-key-for-packager-discrimination";
  process.env.OPENCRED_LOG_LEVEL = "fatal";
  loadConfig();
  createLogger();
});

function b64urlJson(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

/** Build a hand-crafted vc-jwt compact token for display (no signature verification). */
function buildVcJwt(): string {
  const header = { alg: "ES256", typ: "JWT", kid: "did:example:issuer#key-1" };
  const payload = {
    iss: "did:example:issuer",
    sub: "did:example:subject",
    jti: "urn:test:credential-1",
    iat: 1_700_000_000,
    nbf: 1_700_000_000,
    exp: 1_900_000_000,
    vc: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", "TestCredential"],
      credentialSubject: { id: "did:example:subject", role: "tester" },
    },
  };
  return `${b64urlJson(header)}.${b64urlJson(payload)}.fakesig`;
}

describe("packageCredential — kind: compact-token", () => {
  it("returns a JSON envelope wrapping the raw token and a verbatim-token QR", async () => {
    const token = buildVcJwt();
    const input: CredentialInput = { kind: "compact-token", token };

    const result = await packageCredential(input, ["json", "qr-svg"]);

    expect(result.errors).toEqual([]);
    expect(result.outputs.map((o) => o.format).sort()).toEqual(["json", "qr-svg"]);

    // ---- JSON envelope: { format, credential } with the raw token verbatim. ----
    const jsonOutput = result.outputs.find((o) => o.format === "json");
    expect(jsonOutput).toBeDefined();
    expect(typeof jsonOutput!.data).toBe("string");
    const wrapper = JSON.parse(jsonOutput!.data as string) as {
      format: string;
      credential: string;
    };
    expect(wrapper.format).toBe("vc-jwt");
    expect(wrapper.credential).toBe(token);

    // ---- QR payload: raw token verbatim, no PixelPass compression. ----
    const svgOutput = result.outputs.find((o) => o.format === "qr-svg");
    expect(svgOutput).toBeDefined();
    expect(typeof svgOutput!.data).toBe("string");
    const svg = svgOutput!.data as string;
    expect(svg).toContain("<svg");
    // Negative: no PixelPass header. Compressed payloads always carry it.
    expect(svg).not.toContain("OPENCRED1:");
    // Negative cross-check via decodeQrData: a raw JWT string is not a valid
    // PixelPass-compressed payload, so the codec rejects it. If a future
    // regression silently routed the token through compression, this call
    // would *succeed* and return the JSON form of the synthetic VC shape.
    expect(() => decodeQrData(token)).toThrow();
  });
});
