import { describe, it, expect } from "vitest";
import { PDFDocument, PDFDict, PDFName, PDFString, PDFHexString } from "pdf-lib";
import { generatePdf, PDF_CREDENTIAL_INFO_KEY, decodeQrData } from "../index.js";
import type { VerifiableCredential } from "@opencred/vc-core";

const testCredential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:11111111-2222-3333-4444-555555555555",
  type: ["VerifiableCredential", "UniversityDegreeCredential"],
  issuer: { id: "did:web:issuer.example", name: "Example University" },
  validFrom: "2025-01-01T00:00:00Z",
  validUntil: "2030-01-01T00:00:00Z",
  credentialSubject: {
    id: "did:key:zSubjectExample",
    name: "Ada Lovelace",
    degree: "BSc Computer Science",
    nested: { honors: "First Class" },
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: "2025-01-01T00:00:00Z",
    verificationMethod: "did:web:issuer.example#key-1",
    proofPurpose: "assertionMethod",
    proofValue: "zTestSignatureValue",
  },
} as unknown as VerifiableCredential;

/**
 * Read the embedded credential out of a PDF's info dictionary, exactly the
 * way `verifyPdf()` in `@opencred/verification` does (pdf-lib, supporting
 * both literal and hex string encodings).
 */
async function readEmbedded(buf: Buffer): Promise<string | undefined> {
  const pdf = await PDFDocument.load(buf, { updateMetadata: false });
  const infoRef = pdf.context.trailerInfo.Info;
  if (!infoRef) return undefined;
  const info = pdf.context.lookup(infoRef, PDFDict);
  if (!info) return undefined;
  const raw = info.lookup(PDFName.of(PDF_CREDENTIAL_INFO_KEY));
  if (raw instanceof PDFString) return raw.asString();
  if (raw instanceof PDFHexString) return raw.decodeText();
  return undefined;
}

describe("generatePdf", () => {
  it("produces a valid PDF buffer", async () => {
    const buf = await generatePdf(testCredential);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.toString("ascii", 0, 4)).toBe("%PDF");
  });

  it("embeds the credential so verifyPdf can recover it (round-trip)", async () => {
    const buf = await generatePdf(testCredential);
    const embedded = await readEmbedded(buf);
    expect(embedded).toBeTruthy();
    const recovered = JSON.parse(decodeQrData(embedded!));
    expect(recovered.id).toBe(testCredential.id);
    expect(recovered.credentialSubject.name).toBe("Ada Lovelace");
    expect(recovered.proof.cryptosuite).toBe("ecdsa-rdfc-2019");
  });

  it("honors customization (renders without throwing)", async () => {
    const buf = await generatePdf(testCredential, {
      customization: {
        primaryColor: "#FF0000",
        backgroundColor: "#f7f7f7",
        issuerDisplayName: "Custom Issuer",
        footerText: "Custom footer",
      },
    });
    expect(buf.toString("ascii", 0, 4)).toBe("%PDF");
  });

  it("embeds a compact token verbatim when qrPayloadOverride is set", async () => {
    const token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhYmMifQ.sig";
    const buf = await generatePdf(testCredential, { qrPayloadOverride: token });
    expect(await readEmbedded(buf)).toBe(token);
  });

  describe("Digital Signature section — vc-jwt envelope (#693)", () => {
    const b64u = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString("base64url");
    const jwt = [
      b64u({ alg: "ES256", typ: "JWT", kid: "did:web:issuer.example#key-0" }),
      b64u({ iss: "did:web:issuer.example", iat: 1781164628, vc: {} }),
      "c2lnbmF0dXJl",
    ].join(".");
    const envelopeCredential = {
      ...(testCredential as unknown as Record<string, unknown>),
      proof: { type: "JsonWebSignature2020", jwt },
    } as unknown as VerifiableCredential;

    it("derives alg/kid/iat from the embedded JWT — no missing-field warnings", async () => {
      // Before #693 the envelope flowed through the Data-Integrity branch:
      // cryptosuite/created/verificationMethod were absent → three warns and
      // three "(unknown)" rows on the certificate.
      const warns: unknown[] = [];
      const buf = await generatePdf(envelopeCredential, {
        logger: { warn: (...args: unknown[]) => warns.push(args), debug: () => {} },
      });
      expect(buf.toString("ascii", 0, 4)).toBe("%PDF");
      expect(warns).toEqual([]);
    });

    it("falls back to the Data-Integrity branch (with warnings) when proof.jwt is malformed", async () => {
      const warns: unknown[] = [];
      const broken = {
        ...(envelopeCredential as unknown as Record<string, unknown>),
        proof: { type: "JsonWebSignature2020", jwt: "not-a-jwt" },
      } as unknown as VerifiableCredential;
      const buf = await generatePdf(broken, {
        logger: { warn: (...args: unknown[]) => warns.push(args), debug: () => {} },
      });
      expect(buf.toString("ascii", 0, 4)).toBe("%PDF");
      // cryptosuite + created + verificationMethod each warn once.
      expect(warns).toHaveLength(3);
    });

    it("Data-Integrity credentials are unaffected (all fields present, no warnings)", async () => {
      const warns: unknown[] = [];
      const buf = await generatePdf(testCredential, {
        logger: { warn: (...args: unknown[]) => warns.push(args), debug: () => {} },
      });
      expect(buf.toString("ascii", 0, 4)).toBe("%PDF");
      expect(warns).toEqual([]);
    });
  });
});
