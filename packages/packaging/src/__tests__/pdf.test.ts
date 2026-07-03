import { describe, it, expect } from "vitest";
import { PDFDocument, PDFDict, PDFName, PDFString, PDFHexString } from "pdf-lib";
import {
  generatePdf,
  PDF_CREDENTIAL_INFO_KEY,
  decodeQrData,
  flattenCredentialSubject,
} from "../index.js";
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

  describe("flattenCredentialSubject — nested objects/arrays (no [object Object])", () => {
    it("renders a shallow (one-level) nested object as an indented group", () => {
      const rows = flattenCredentialSubject({
        id: "did:key:zSubject",
        name: "Ada Lovelace",
        nested: { honors: "First Class" },
      });
      // `id` is dropped (shown in the "Issued to" strip).
      expect(rows).toEqual([
        { label: "Name", value: "Ada Lovelace", depth: 0 },
        { label: "Nested", value: "", depth: 0 },
        { label: "Honors", value: "First Class", depth: 1 },
      ]);
    });

    it("recurses past one level — the APEPDCL bug: deep objects never become [object Object]", () => {
      // Mirrors the reported shape: credentialSubject.customerProfile.idRef is
      // itself an object (two levels deep); pre-fix it rendered "[object Object]".
      const rows = flattenCredentialSubject({
        id: "did:dedi:apepdcl:consumers:1111230601018997/26956075",
        customerProfile: {
          customerNumber: "1111230601018997",
          idRef: { type: "AADHAAR", value: "xxxx-1234" },
          energyResources: [{ meterNumber: "M-1", capacity: "5kW" }],
        },
        customerDetails: {
          fullName: "KANTIPUDI",
          installationAddress: { line1: "Plot 7", city: "Visakhapatnam", pincode: "530001" },
          serviceConnectionDate: "2020-07-29T00:00:00+05:30",
        },
      });
      // No row's value is the [object Object] stringification.
      expect(rows.every((r) => r.value !== "[object Object]")).toBe(true);
      // The deep leaves surface as their own rows.
      expect(rows).toContainEqual({ label: "Type", value: "AADHAAR", depth: 2 });
      expect(rows).toContainEqual({ label: "Value", value: "xxxx-1234", depth: 2 });
      expect(rows).toContainEqual({ label: "City", value: "Visakhapatnam", depth: 2 });
      // Array of objects → group header + numbered items, then their leaves.
      expect(rows).toContainEqual({ label: "Energy Resources", value: "", depth: 1 });
      expect(rows).toContainEqual({ label: "Item 1", value: "", depth: 2 });
      expect(rows).toContainEqual({ label: "Meter Number", value: "M-1", depth: 3 });
    });

    it("collapses an array of primitives onto one comma-joined row", () => {
      const rows = flattenCredentialSubject({ tariffs: ["LT-1", "LT-2", "HT-3"] });
      expect(rows).toEqual([{ label: "Tariffs", value: "LT-1, LT-2, HT-3", depth: 0 }]);
    });

    it("renders empty objects/arrays and null as an em-dash row", () => {
      const rows = flattenCredentialSubject({
        empties: {},
        list: [],
        missing: null,
      });
      expect(rows).toEqual([
        { label: "Empties", value: "—", depth: 0 },
        { label: "List", value: "—", depth: 0 },
        { label: "Missing", value: "—", depth: 0 },
      ]);
    });

    it("stringifies primitive leaves (numbers, booleans, zero, false)", () => {
      const rows = flattenCredentialSubject({
        load: 5,
        active: true,
        balance: 0,
        disconnected: false,
      });
      expect(rows).toEqual([
        { label: "Load", value: "5", depth: 0 },
        { label: "Active", value: "true", depth: 0 },
        { label: "Balance", value: "0", depth: 0 },
        { label: "Disconnected", value: "false", depth: 0 },
      ]);
    });

    it("paginates (does not cascade) when a nested subject overflows one page", async () => {
      // A subject that flattens to ~160 rows. Before the page-break guard, the
      // first row past the page bottom made field()'s stale `y` re-trigger a
      // page break on every subsequent row — a runaway cascade (hundreds of
      // near-empty pages). It must instead paginate to a small, bounded count.
      const subject: Record<string, unknown> = { id: "did:example:overflow" };
      for (let g = 0; g < 8; g++) {
        const group: Record<string, unknown> = {};
        for (let i = 0; i < 6; i++) group[`field_${i}`] = `value ${g}-${i}`;
        group.items = [
          { a: "a0", b: "b0", c: "c0" },
          { a: "a1", b: "b1", c: "c1" },
          { a: "a2", b: "b2", c: "c2" },
        ];
        subject[`group_${g}`] = group;
      }
      const big = {
        ...(testCredential as unknown as Record<string, unknown>),
        credentialSubject: subject,
      } as unknown as VerifiableCredential;
      const buf = await generatePdf(big);
      const pdf = await PDFDocument.load(buf);
      // ~160 rows at ~15pt spans a handful of pages; the cascade bug produced
      // hundreds. Assert a sane upper bound well below any cascade.
      expect(pdf.getPageCount()).toBeLessThanOrEqual(8);
      expect(pdf.getPageCount()).toBeGreaterThan(1);
    });

    it("generatePdf renders a deeply-nested subject without throwing", async () => {
      const deep = {
        ...(testCredential as unknown as Record<string, unknown>),
        credentialSubject: {
          id: "did:key:zSubject",
          customerProfile: {
            idRef: { authority: { name: "UIDAI", scheme: { version: "2" } } },
          },
        },
      } as unknown as VerifiableCredential;
      const buf = await generatePdf(deep);
      expect(buf.toString("ascii", 0, 4)).toBe("%PDF");
    });
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
