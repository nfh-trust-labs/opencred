/**
 * Unit tests for `verifyPdf`.
 *
 * Strategy: build PDFs in-process with `pdf-lib` so each test owns the bytes
 * it's verifying. We don't pull in the upstream `apps/server` PDF generator
 * (that would be a circular layering) — instead, the test fixtures embed
 * the same `OpenCredCredential` info-dict key that the issuance side writes,
 * proving that the contract between issuance and verification is the
 * info-dict key + value shape, not a particular PDF layout.
 *
 * The credential round-trip itself is tested with a real signing path
 * (P-256 ECDSA Data Integrity proof + a mock DID resolver) so the test
 * exercises the full verifyCredential pipeline through verifyPdf, not just
 * the PDF parsing surface.
 */

import { describe, expect, it } from "vitest";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { createRequire } from "node:module";
import { PDFDict, PDFDocument, PDFName, PDFString } from "pdf-lib";

import { signCredential } from "@opencred/crypto";
import type {
  DIDDocument,
  DIDResolutionResult,
  DIDResolver,
  VerificationMethod,
} from "@opencred/did";
import type { UnsignedCredential, VerifiableCredential } from "@opencred/vc-core";

import { PDF_CREDENTIAL_INFO_KEY, verifyPdf } from "../pdf-verifier.js";

// PixelPass is CJS — same access pattern as the rest of the package.
const require = createRequire(import.meta.url);
const pixelpass = require("@mosip/pixelpass") as {
  generateQRData: (data: string, header?: string) => string;
};

/** Construct a minimal PDF carrying the given embedded credential value. */
async function buildPdf(embedded: string | undefined): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.addPage([400, 400]);
  doc.setTitle("Test Certificate");
  if (embedded !== undefined) {
    // pdf-lib does not expose a setter for arbitrary info-dict keys, so we
    // reach into the underlying dict directly — same surface the verifier
    // reads from.
    const infoRef = doc.context.trailerInfo.Info;
    if (!infoRef) {
      throw new Error("pdf-lib did not produce an info dict — fixture invariant broken");
    }
    const infoDict = doc.context.lookup(infoRef, PDFDict);
    infoDict.set(PDFName.of(PDF_CREDENTIAL_INFO_KEY), PDFString.of(embedded));
  }
  return doc.save();
}

function createTestCredential(): UnsignedCredential {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:test-pdf-credential-001",
    type: ["VerifiableCredential"],
    issuer: "did:example:test-issuer",
    validFrom: "2026-01-01T00:00:00Z",
    credentialSubject: {
      id: "did:example:holder",
      name: "Test Subject",
    },
  };
}

function generateTestKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

function createMockResolver(did: string, vm: VerificationMethod): DIDResolver {
  return {
    resolve: async (input: string): Promise<DIDResolutionResult> => {
      if (input !== did) {
        return {
          didDocument: null,
          didResolutionMetadata: { error: "notFound" },
          didDocumentMetadata: {},
        };
      }
      return {
        didDocument: {
          "@context": "https://www.w3.org/ns/did/v1",
          id: did,
          verificationMethod: [vm],
          assertionMethod: [vm.id],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

describe("verifyPdf", () => {
  it("returns INVALID with a structured check when the PDF has no embedded credential", async () => {
    const pdf = await buildPdf(undefined);

    const result = await verifyPdf(pdf);

    expect(result.verified).toBe(false);
    expect(result.code).toBe("INVALID");
    expect(result.checks).toHaveLength(1);
    expect(result.checks[0].name).toBe("pdf-embedded-credential");
    expect(result.checks[0].passed).toBe(false);
    expect(result.checks[0].detail).toMatch(/legacy PDF|not produced by OpenCred/i);
  });

  it("returns INVALID with `pdf-parse` failure when bytes are not a valid PDF", async () => {
    const garbage = new Uint8Array([0x00, 0x01, 0x02, 0x03]);

    const result = await verifyPdf(garbage);

    expect(result.verified).toBe(false);
    expect(result.code).toBe("INVALID");
    expect(result.checks[0].name).toBe("pdf-parse");
    expect(result.checks[0].passed).toBe(false);
  });

  it("returns missing-key failure even when the PDF has a populated info dict", async () => {
    // A real legacy OpenCred PDF carries Title / Author / Subject /
    // Producer in its info dict — only `OpenCredCredential` is absent.
    // Pin that the verifier correctly distinguishes "info dict exists
    // but key missing" from "no info dict at all", since they take
    // separate code paths in `extractEmbeddedCredential`.
    const doc = await PDFDocument.create();
    doc.addPage([400, 400]);
    doc.setTitle("Some Other Certificate");
    doc.setAuthor("OpenCred (legacy)");
    doc.setSubject("Credential: urn:test:legacy");
    doc.setProducer("PDFKit");
    const bytes = await doc.save();

    const result = await verifyPdf(bytes);

    expect(result.verified).toBe(false);
    expect(result.code).toBe("INVALID");
    expect(result.checks[0].name).toBe("pdf-embedded-credential");
    expect(result.checks[0].passed).toBe(false);
  });

  it("returns a distinct `pdf-encrypted` check for encrypted PDFs", async () => {
    // pdf-lib does not write encryption itself, so we hand-craft the
    // minimal cue that triggers its `isEncrypted` getter: an /Encrypt
    // entry in the trailer. The point is to confirm `verifyPdf`
    // surfaces encryption distinctly rather than falling through to the
    // legacy-PDF message; the encryption itself doesn't have to be
    // valid for that contract test.
    const doc = await PDFDocument.create();
    doc.addPage([400, 400]);
    // Inject a synthetic /Encrypt indirect reference so `doc.isEncrypted`
    // returns true on the next load.
    const encryptDict = doc.context.obj({
      Filter: PDFName.of("Standard"),
      V: 1,
      R: 2,
      O: PDFString.of(""),
      U: PDFString.of(""),
      P: -1,
    });
    const encryptRef = doc.context.register(encryptDict);
    doc.context.trailerInfo.Encrypt = encryptRef;
    const bytes = await doc.save({ updateFieldAppearances: false });

    const result = await verifyPdf(bytes);

    expect(result.verified).toBe(false);
    expect(result.code).toBe("INVALID");
    expect(result.checks[0].name).toBe("pdf-encrypted");
    expect(result.checks[0].detail).toMatch(/encrypted/i);
  });

  it("rejects an unrecognized embedded value with `pdf-embedded-credential` failure", async () => {
    // Not PixelPass, not JSON, not a JWT — verifier can't classify it.
    const pdf = await buildPdf("this is not a credential format");

    const result = await verifyPdf(pdf);

    expect(result.verified).toBe(false);
    expect(result.code).toBe("INVALID");
    expect(result.checks[0].name).toBe("pdf-embedded-credential");
    expect(result.checks[0].detail).toMatch(/format could not be recognized/i);
  });

  it("verifies a signed credential round-tripped through PixelPass + PDF embedding", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
    const did = "did:example:test-issuer";
    const vmId = `${did}#key-1`;
    const credentialUnsigned = createTestCredential();

    const signed = (await signCredential(
      credentialUnsigned,
      { id: vmId, privateKey, publicKey, algorithm: "P-256" },
      { verificationMethod: vmId, proofPurpose: "assertionMethod" },
    )) as VerifiableCredential;

    const resolver = createMockResolver(did, {
      id: vmId,
      type: "JsonWebKey2020",
      controller: did,
      publicKeyJwk: publicJwk,
    } as VerificationMethod);

    // Mirror the issuance side: PixelPass-compress the credential (no
    // header — bare payload, matching the emitter) and embed it in the PDF
    // info dictionary under `OpenCredCredential`.
    const compressed = pixelpass.generateQRData(JSON.stringify(signed));
    const pdf = await buildPdf(compressed);

    const result = await verifyPdf(pdf, { didResolver: resolver });

    expect(result.verified).toBe(true);
    expect(result.code).toBe("VALID");
  });

  it("verifies an embedded plain JSON credential (non-PixelPass embedding)", async () => {
    const { privateKey, publicKey } = generateTestKeyPair();
    const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
    const did = "did:example:test-issuer";
    const vmId = `${did}#key-1`;
    const credentialUnsigned = createTestCredential();
    const signed = (await signCredential(
      credentialUnsigned,
      { id: vmId, privateKey, publicKey, algorithm: "P-256" },
      { verificationMethod: vmId, proofPurpose: "assertionMethod" },
    )) as VerifiableCredential;

    const resolver = createMockResolver(did, {
      id: vmId,
      type: "JsonWebKey2020",
      controller: did,
      publicKeyJwk: publicJwk,
    } as VerificationMethod);

    // Embed the raw JSON instead of the PixelPass blob — the format
    // detector sees a leading `{` and routes through the JSON branch.
    const pdf = await buildPdf(JSON.stringify(signed));

    const result = await verifyPdf(pdf, { didResolver: resolver });

    expect(result.verified).toBe(true);
    expect(result.code).toBe("VALID");
  });

  it("forwards verifier failures through verifyPdf without altering the result code", async () => {
    // Sign with one key, give the resolver a different one. Signature
    // mismatch surfaces as INVALID with the data-integrity check failing,
    // but verifyPdf must not relabel the code.
    const { privateKey, publicKey } = generateTestKeyPair();
    const { publicKey: wrongPublicKey } = generateTestKeyPair();
    const wrongJwk = wrongPublicKey.export({ format: "jwk" }) as Record<string, unknown>;
    const did = "did:example:test-issuer";
    const vmId = `${did}#key-1`;
    const credentialUnsigned = createTestCredential();
    const signed = (await signCredential(
      credentialUnsigned,
      { id: vmId, privateKey, publicKey, algorithm: "P-256" },
      { verificationMethod: vmId, proofPurpose: "assertionMethod" },
    )) as VerifiableCredential;

    const resolver = createMockResolver(did, {
      id: vmId,
      type: "JsonWebKey2020",
      controller: did,
      publicKeyJwk: wrongJwk,
    } as VerificationMethod);

    const compressed = pixelpass.generateQRData(JSON.stringify(signed));
    const pdf = await buildPdf(compressed);

    const result = await verifyPdf(pdf, { didResolver: resolver });

    expect(result.verified).toBe(false);
    expect(result.code).toBe("INVALID");
  });
});
