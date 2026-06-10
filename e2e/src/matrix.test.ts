/**
 * Credential matrix — issue + verify every valid
 * {algorithm × proof format} cell against the real Docker image, through
 * both verifiers (the public @opencred/verify SDK and the server's
 * /v1/credentials/verify), plus tamper rejection, export round-trips, and
 * the documented exclusions.
 *
 * Requirements: a docker daemon and OPENCRED_E2E_IMAGE pointing at a built
 * server image (e.g. `docker build -f apps/server/Dockerfile -t opencred-server:e2e .`).
 * The suite skips loudly when either is missing.
 *
 * DeDi key-lifecycle cells live in dedi-lifecycle.test.ts (env-gated).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createVerifier } from "@opencred/verify";
import {
  E2E_IMAGE,
  dockerAvailable,
  startServer,
  type MatrixAlgorithm,
  type ServerContainer,
} from "./docker.js";
import {
  issueCredential,
  verifyViaServer,
  packageCredential,
  type ProofFormat,
} from "./server-client.js";

const runnable = Boolean(E2E_IMAGE) && dockerAvailable();
if (!runnable) {
  // eslint-disable-next-line no-console
  console.warn(
    "[e2e-matrix] SKIPPED — set OPENCRED_E2E_IMAGE to a built server image and ensure docker is running.",
  );
}

/** Valid {algorithm × proof format} cells. RSA × data-integrity is excluded by design. */
const MATRIX: Array<{ algorithm: MatrixAlgorithm; formats: ProofFormat[]; port: number }> = [
  { algorithm: "P-256", formats: ["vc-jwt", "data-integrity", "sd-jwt-vc"], port: 3110 },
  { algorithm: "P-384", formats: ["vc-jwt", "data-integrity", "sd-jwt-vc"], port: 3111 },
  { algorithm: "Ed25519", formats: ["vc-jwt", "data-integrity", "sd-jwt-vc"], port: 3112 },
  { algorithm: "RSA-2048", formats: ["vc-jwt", "sd-jwt-vc"], port: 3113 },
];

const verify = createVerifier();

function tamper(credential: Record<string, unknown> | string): Record<string, unknown> | string {
  if (typeof credential === "string") {
    // Compact token: corrupt the issuer-JWT signature segment.
    const [jwt, ...rest] = credential.split("~");
    const parts = jwt.split(".");
    parts[2] = parts[2].slice(0, -8) + (parts[2].endsWith("AAAA") ? "BBBBBBBB" : "AAAAAAAA");
    return [parts.join("."), ...rest].join("~");
  }
  const copy = structuredClone(credential);
  (copy.credentialSubject as Record<string, unknown>).name = "Mallory";
  return copy;
}

describe.runIf(runnable).each(MATRIX)(
  "matrix: $algorithm",
  ({ algorithm, formats, port }) => {
    let server: ServerContainer;

    beforeAll(async () => {
      server = await startServer(algorithm, port);
    });

    afterAll(() => {
      server?.stop();
    });

    describe.each(formats.map((f) => ({ format: f })))("$format", ({ format }) => {
      it("issues, verifies via SDK and server, rejects tampering", async () => {
        const issued = await issueCredential(server.baseUrl, format, {
          id: `did:example:holder-${algorithm}-${format}`,
        });
        expect(issued.status, JSON.stringify(issued.error)).toBe(200);
        const credential = issued.credential!;

        const sdkResult = await verify(credential as never);
        expect(sdkResult.code, JSON.stringify(sdkResult.checks)).toBe("VALID");
        expect(sdkResult.verified).toBe(true);

        const serverResult = await verifyViaServer(server.baseUrl, credential);
        expect(serverResult.code, JSON.stringify(serverResult.checks)).toBe("VALID");

        const tampered = tamper(credential);
        const tamperedResult = await verify(tampered as never);
        expect(tamperedResult.verified).toBe(false);
      });
    });

    it("rejects an expired credential at verification (EXPIRED)", async () => {
      const issued = await issueCredential(
        server.baseUrl,
        formats[0],
        { id: "did:example:expired-holder" },
        { validFrom: "2020-01-01T00:00:00Z", validUntil: "2021-01-01T00:00:00Z" },
      );
      expect(issued.status, JSON.stringify(issued.error)).toBe(200);
      const result = await verify(issued.credential as never);
      expect(result.verified).toBe(false);
      expect(result.code).toBe("EXPIRED");
    });
  },
);

describe.runIf(runnable)("documented exclusions", () => {
  let server: ServerContainer;

  beforeAll(async () => {
    server = await startServer("RSA-2048", 3114);
  });

  afterAll(() => {
    server?.stop();
  });

  it("RSA × data-integrity is rejected with a clear error", async () => {
    const issued = await issueCredential(server.baseUrl, "data-integrity", {});
    expect(issued.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(issued.error)).toMatch(/RSA/i);
  });
});

describe.runIf(runnable)("export round-trips (P-256)", () => {
  let server: ServerContainer;

  beforeAll(async () => {
    server = await startServer("P-256", 3115);
  });

  afterAll(() => {
    server?.stop();
  });

  it.each([{ format: "vc-jwt" as ProofFormat }, { format: "data-integrity" as ProofFormat }])(
    "$format → PDF package → SDK verify.pdf",
    async ({ format }) => {
      const issued = await issueCredential(server.baseUrl, format, {
        id: `did:example:pdf-${format}`,
      });
      expect(issued.status, JSON.stringify(issued.error)).toBe(200);

      const outputs = await packageCredential(server.baseUrl, issued.credential!, ["pdf", "json"]);
      const pdf = outputs.find((o) => o.format === "pdf")!;
      expect(pdf).toBeDefined();
      const pdfBytes = new Uint8Array(Buffer.from(pdf.data, "base64"));
      expect(Buffer.from(pdfBytes.slice(0, 5)).toString()).toBe("%PDF-");

      const result = await verify.pdf(pdfBytes);
      expect(result.code, JSON.stringify(result.checks)).toBe("VALID");

      // The JSON export must round-trip through the verifier too.
      const json = outputs.find((o) => o.format === "json")!;
      const reparsed = JSON.parse(json.data) as Record<string, unknown>;
      const jsonResult = await verify(reparsed);
      expect(jsonResult.code).toBe("VALID");
    },
  );

  it("sd-jwt-vc compact token → PDF package → SDK verify.pdf", async () => {
    const issued = await issueCredential(server.baseUrl, "sd-jwt-vc", {
      id: "did:example:pdf-sdjwt",
    });
    expect(issued.status, JSON.stringify(issued.error)).toBe(200);

    const outputs = await packageCredential(server.baseUrl, issued.credential!, ["pdf"]);
    const pdf = outputs.find((o) => o.format === "pdf")!;
    const result = await verify.pdf(new Uint8Array(Buffer.from(pdf.data, "base64")));
    expect(result.code, JSON.stringify(result.checks)).toBe("VALID");
  });
});
