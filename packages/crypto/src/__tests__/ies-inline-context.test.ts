import { describe, it, expect } from "vitest";
import { canonicalize } from "../data-integrity.js";

/**
 * Issue #764 — DigiLocker does not resolve `@import`, so IES v1.2
 * credentials also list the flat `context.inline.jsonld`. These tests pin
 * the one property that makes that safe: listed *before* the v1.2 context,
 * the inline context changes nothing in the canonical RDF, so signatures
 * and meaning are identical to a credential that lists v1.2 alone.
 */
const W3C_V2 = "https://www.w3.org/ns/credentials/v2";
const IES_V1_2 =
  "https://india-energy-stack.github.io/ies-accelerator/schemas/ElectricityCredential/v1.2/context.jsonld";
const IES_V1_2_INLINE =
  "https://india-energy-stack.github.io/ies-accelerator/schemas/ElectricityCredential/v1.2/context.inline.jsonld";

// Exercises every field DigiLocker reported as MISSING_KEY, including the
// nested QuantitativeValue ({value, unit}) and GeoJSON shapes.
const SUBJECT = {
  id: "did:example:consumer",
  customerProfile: {
    customerNumber: "900000902588",
    idRef: { issuedBy: "did:web:issuer.example", subjectId: "ca:900000902588" },
    energyResources: [
      {
        id: "urn:ies:meter:LSW002975",
        type: "METER",
        meterCapability: "AMI",
        ratedPower: { value: 5, unit: "kW" },
      },
    ],
    consumptionProfiles: [
      {
        meterId: "LSW002975",
        tariffCategoryCode: "LT-1",
        premisesType: "RESIDENTIAL",
        connectionType: "SINGLE_PHASE",
        sanctionedLoad: { value: 3, unit: "kW" },
      },
    ],
  },
  customerDetails: {
    fullName: "Test Consumer",
    serviceConnectionDate: "2020-01-01",
    installationAddress: {
      geo: { type: "Point", coordinates: [72.8777, 19.076] },
      address: {
        streetAddress: "1 Example Road",
        extendedAddress: "Flat 2",
        addressLocality: "Mumbai",
        addressRegion: "MH",
        addressCountry: "IN",
        postalCode: "400001",
      },
    },
  },
};

const credential = (context: string[]) => ({
  "@context": context,
  id: "urn:uuid:5f507370-6684-5bc9-8539-8cd5bc278337",
  type: ["VerifiableCredential", "ElectricityCredential"],
  issuer: "did:web:issuer.example",
  validFrom: "2026-09-01T00:00:00Z",
  credentialSubject: SUBJECT,
});

describe("IES v1.2 inline context (issue #764)", () => {
  it("leaves the canonical RDF byte-identical when listed before the v1.2 context", async () => {
    const v12Only = await canonicalize(credential([W3C_V2, IES_V1_2]));
    const withInline = await canonicalize(credential([W3C_V2, IES_V1_2_INLINE, IES_V1_2]));
    expect(withInline).toBe(v12Only);
  });

  it("is rejected by strict canonicalization when listed after the v1.2 context", async () => {
    // Later contexts win: the inline file's plain `customerProfile` /
    // `customerDetails` definitions would drop v1.2's scoped contexts,
    // leaving values such as `type: "METER"` undefined.
    await expect(canonicalize(credential([W3C_V2, IES_V1_2, IES_V1_2_INLINE]))).rejects.toThrow(
      /is not defined in the credential's JSON-LD @context/,
    );
  });
});
