import { describe, it, expect } from "vitest";
import { canonicalJsonSha256 } from "@opencred/shared";
import { createRegistry, Validator } from "../index.js";
import { getCategoryForSchema } from "../schema-categories.js";
import {
  iesElectricityCredentialV1_2Definition,
  iesElectricityCredentialV1_2Schema,
} from "../schemas/ies-electricity-credential-v1-2.js";
import {
  iesMeterDataCredentialV0_6Definition,
  iesMeterDataCredentialV0_6Schema,
} from "../schemas/ies-meter-data-credential-v0-6.js";

/**
 * Fixture: credentialSubject of the upstream ElectricityCredential v1.2
 * example (schemas/ElectricityCredential/v1.2/examples/example.json in the
 * India-Energy-Stack/ies-accelerator repo).
 */
const validElectricitySubject = {
  id: "did:example:customer:abc123",
  customerProfile: {
    customerNumber: "UTIL-2025-001234567",
    idRef: {
      issuedBy: "did:web:ssa.gov",
      subjectId: "ssa.gov:XXX-XX-1234",
    },
    energyResources: [
      {
        id: "did:web:example-utility.com:assets:meter:MET2025789456123",
        type: "METER",
        attributes: {
          meterCapability: "AMI",
          energyDirection: "Forward",
          location: {
            geo: {
              type: "Point",
              coordinates: [-122.4194, 37.7749],
            },
          },
        },
        parentResources: ["did:web:example-utility.com:assets:feeder:DT-FEEDER-A1-001"],
      },
      {
        id: "did:web:example-utility.com:assets:solar-plant:DER-SOLAR-001",
        type: "SOLAR_PV",
        attributes: {
          maxExport: {
            value: 3,
            unit: "kW",
          },
          make: "SunPower Corporation",
          model: "SPR-X22-360",
          commissioningDate: "2025-01-12T00:00:00-05:00",
        },
        parentResources: ["did:web:example-utility.com:assets:meter:MET2025789456123"],
      },
      {
        id: "did:web:example-utility.com:assets:wind-farm:DER-WIND-001",
        type: "WIND",
        attributes: {
          maxExport: {
            value: 1.5,
            unit: "kW",
          },
          make: "Windmill Co.",
          model: "WM-MICRO-150",
          commissioningDate: "2025-03-01T00:00:00-05:00",
        },
        parentResources: ["did:web:example-utility.com:assets:meter:MET2025789456123"],
      },
      {
        id: "did:web:example-utility.com:assets:bess:BESS-001",
        type: "BESS",
        attributes: {
          maxExport: {
            value: 5,
            unit: "kW",
          },
          maxImport: {
            value: 5,
            unit: "kW",
          },
          storageCapacity: {
            value: 10,
            unit: "kWh",
          },
          storageType: "LithiumIon",
          commissioningDate: "2025-01-12T00:00:00-05:00",
        },
        parentResources: ["did:web:example-utility.com:assets:meter:MET2025789456123"],
      },
      {
        id: "did:web:example-utility.com:assets:bess:BESS-002",
        type: "BESS",
        attributes: {
          maxExport: {
            value: 2.5,
            unit: "kW",
          },
          maxImport: {
            value: 2.5,
            unit: "kW",
          },
          storageCapacity: {
            value: 5,
            unit: "kWh",
          },
          storageType: "LithiumIon",
          commissioningDate: "2025-06-01T00:00:00-05:00",
        },
        parentResources: ["did:web:example-utility.com:assets:meter:MET2025789456123"],
      },
    ],
    consumptionProfiles: [
      {
        meterId: "did:web:example-utility.com:assets:meter:MET2025789456123",
        sanctionedLoad: {
          value: 5,
          unit: "kW",
        },
        contractMaxDemand: {
          value: 4,
          unit: "kW",
        },
        tariffCategoryCode: "RES-01",
        premisesType: "Residential",
        connectionType: "Single-phase",
      },
    ],
  },
  customerDetails: {
    fullName: "Jane Doe",
    installationAddress: {
      geo: {
        type: "Point",
        coordinates: [-122.4194, 37.7749],
      },
      address: {
        streetAddress: "123 Energy Street, Unit 4",
        addressLocality: "Metro City",
        addressRegion: "Example State",
        postalCode: "12345",
        addressCountry: "US",
      },
    },
    serviceConnectionDate: "2025-01-10T00:00:00-05:00",
  },
};

/**
 * Fixture: credentialSubject of the upstream MeterDataCredential v0.6
 * interval-profile example
 * (schemas/MeterDataCredential/v0.6/examples/example-interval-profile.json).
 */
const validMeterDataSubject = {
  id: "did:dedi:bescom:consumers:RR-1234",
  meterData: [
    {
      "@context":
        "https://india-energy-stack.github.io/ies-accelerator/schemas/MeterData/v0.6/context.jsonld",
      "@type": "PayloadDescriptorProfile",
      profileType: "DESCRIPTOR",
      id: "DESC-INTERVAL-BLR-2026Q1",
      payloadDescriptorSets: [
        {
          name: "IntervalLoadSurveySet",
          payloadDescriptors: [
            {
              readingType: "kWh imp block",
              name: "Active energy import – block incremental",
              unit: "kWh",
              flowDirection: "IMPORT",
              reportedMode: "USAGE",
              obis: "1.0.1.29.0.255",
            },
            {
              readingType: "kWh exp block",
              name: "Active energy export – block incremental",
              unit: "kWh",
              flowDirection: "EXPORT",
              reportedMode: "USAGE",
              obis: "1.0.2.29.0.255",
            },
          ],
          compactSequences: [
            {
              name: "IntervalSeq",
              sequenceItems: [
                {
                  readingType: "kWh imp block",
                },
                {
                  readingType: "kWh exp block",
                },
              ],
            },
          ],
        },
      ],
    },
    {
      "@context":
        "https://india-energy-stack.github.io/ies-accelerator/schemas/MeterData/v0.6/context.jsonld",
      "@type": "IntervalProfile",
      profileType: "INTERVAL",
      meterRefs: [
        {
          scheme: "DID",
          value: "did:dedi:bescom:assets:meter:BESCOM-SM-2025-654321",
        },
      ],
      serviceDeliveryPointRefs: [
        {
          scheme: "DID",
          value: "did:dedi:bescom:connections:SDP-BLR-A-12345",
        },
      ],
      payloadDescriptorSetRef: "DESC-INTERVAL-BLR-2026Q1",
      compactSequenceRef: "IntervalSeq",
      intervalPeriod: {
        start: "2026-01-01T00:00:00+05:30",
        duration: "PT15M",
      },
      intervals: [
        {
          id: 0,
          payloads: [1.234, 0.0],
        },
        {
          id: 1,
          payloads: [1.187, 0.0],
        },
        {
          id: 2,
          payloads: [1.301, 0.0],
        },
        {
          id: 3,
          payloads: [1.256, 0.0],
        },
      ],
    },
  ],
};

/** Collect every `$ref` string in a schema document. */
function collectRefs(node: unknown, refs: string[] = []): string[] {
  if (Array.isArray(node)) {
    for (const item of node) collectRefs(item, refs);
  } else if (node && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      if (key === "$ref" && typeof value === "string") refs.push(value);
      else collectRefs(value, refs);
    }
  }
  return refs;
}

/** Collect every occurrence of the given keyword names in a schema document. */
function collectKeywords(node: unknown, names: Set<string>, hits: string[] = []): string[] {
  if (Array.isArray(node)) {
    for (const item of node) collectKeywords(item, names, hits);
  } else if (node && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      if (names.has(key)) hits.push(key);
      collectKeywords(value, names, hits);
    }
  }
  return hits;
}

const schemas: Array<[string, Record<string, unknown>]> = [
  ["ies/electricity-credential/v1.2", iesElectricityCredentialV1_2Schema],
  ["ies/meter-data-credential/v0.6", iesMeterDataCredentialV0_6Schema],
];

describe("IES schemas (bundled)", () => {
  it("have the expected IDs and versions", () => {
    expect(iesElectricityCredentialV1_2Definition.id).toBe("ies/electricity-credential/v1.2");
    expect(iesElectricityCredentialV1_2Definition.version).toBe("1.2.0");
    expect(iesMeterDataCredentialV0_6Definition.id).toBe("ies/meter-data-credential/v0.6");
    expect(iesMeterDataCredentialV0_6Definition.version).toBe("0.6.0");
  });

  it("are registered in the default registry with the utility category", () => {
    const registry = createRegistry();
    for (const [id] of schemas) {
      expect(registry.listSchemas()).toContain(id);
      expect(registry.getSchema(id).category).toBe("utility");
    }
  });

  it("map to the utility category via getCategoryForSchema (dotted versions)", () => {
    expect(getCategoryForSchema("ies/electricity-credential/v1.2")).toBe("utility");
    expect(getCategoryForSchema("ies/meter-data-credential/v0.6")).toBe("utility");
  });

  it("have stable canonical checksums", () => {
    for (const def of [
      iesElectricityCredentialV1_2Definition,
      iesMeterDataCredentialV0_6Definition,
    ]) {
      expect(def.checksum).toMatch(/^[0-9a-f]{64}$/);
      expect(def.checksum).toBe(canonicalJsonSha256(def.schema));
    }
  });

  it("have IES source provenance pointing at the canonical publications", () => {
    for (const def of [
      iesElectricityCredentialV1_2Definition,
      iesMeterDataCredentialV0_6Definition,
    ]) {
      expect(def.source.kind).toBe("referenced");
      expect(def.source.upstreamOwner).toBe("India Energy Stack");
    }
    expect(iesElectricityCredentialV1_2Definition.source.upstreamUrl).toBe(
      "https://schema.beckn.io/ElectricityCredential/1.2/schema.json",
    );
    expect(iesMeterDataCredentialV0_6Definition.source.upstreamUrl).toBe(
      "https://india-energy-stack.github.io/ies-accelerator/schemas/MeterDataCredential/v0.6/schema.json",
    );
  });

  it("contain no remote $refs — every $ref is a local JSON pointer", () => {
    for (const [id, schema] of schemas) {
      const refs = collectRefs(schema);
      expect(refs.length).toBeGreaterThan(0);
      const remote = refs.filter((r) => !r.startsWith("#/"));
      expect(remote, `${id} must be fully self-contained`).toEqual([]);
    }
  });

  it("every local $ref resolves to an existing $defs entry", () => {
    for (const [id, schema] of schemas) {
      const defs = schema["$defs"] as Record<string, unknown>;
      for (const ref of collectRefs(schema)) {
        const name = ref.replace("#/$defs/", "");
        expect(defs[name], `${id}: dangling $ref ${ref}`).toBeDefined();
      }
    }
  });

  it("contain no keywords rejected by Ajv strict mode", () => {
    for (const [id, schema] of schemas) {
      const hits = collectKeywords(
        schema,
        new Set(["$anchor", "x-jsonld", "$dynamicRef", "$dynamicAnchor"]),
      );
      expect(hits, `${id} must not carry strict-mode-unknown keywords`).toEqual([]);
    }
  });

  describe("ElectricityCredential v1.2", () => {
    const registry = createRegistry();
    const validator = new Validator(registry);

    it("follows the W3C VC 2.0 envelope pattern", () => {
      const props = iesElectricityCredentialV1_2Schema["properties"] as Record<string, unknown>;
      expect(props["@context"]).toBeDefined();
      expect(props["type"]).toBeDefined();
      expect(props["issuer"]).toBeDefined();
      expect(props["credentialSubject"]).toBeDefined();
      const required = iesElectricityCredentialV1_2Schema["required"] as string[];
      expect(required).toContain("@context");
      expect(required).toContain("credentialSubject");
    });

    it("compiles offline and accepts the upstream example subject", () => {
      const result = validator.validateCredentialSubject(
        "ies/electricity-credential/v1.2",
        validElectricitySubject,
      );
      expect(result.errors).toEqual([]);
      expect(result.valid).toBe(true);
    });

    it("rejects a subject missing customerProfile", () => {
      const result = validator.validateCredentialSubject("ies/electricity-credential/v1.2", {
        id: "did:example:customer:abc123",
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.field === "customerProfile")).toBe(true);
    });

    it("rejects a subject with a malformed customerProfile", () => {
      const result = validator.validateCredentialSubject("ies/electricity-credential/v1.2", {
        customerProfile: { energyResources: "not-an-array" },
      });
      expect(result.valid).toBe(false);
    });
  });

  describe("MeterDataCredential v0.6", () => {
    const registry = createRegistry();
    const validator = new Validator(registry);

    it("exposes credentialSubject for envelope extraction (beckn allOf dropped)", () => {
      expect(iesMeterDataCredentialV0_6Schema["allOf"]).toBeUndefined();
      const props = iesMeterDataCredentialV0_6Schema["properties"] as Record<string, unknown>;
      expect(props["credentialSubject"]).toBeDefined();
    });

    it("embeds the MeterData v0.6 payload schema inline", () => {
      const defs = iesMeterDataCredentialV0_6Schema["$defs"] as Record<string, unknown>;
      expect(defs["MeterData"]).toBeDefined();
      // spot-check a few payload definitions carried over from MeterData/v0.6
      expect(defs["EnergyData"]).toBeDefined();
      expect(defs["IntervalProfile"]).toBeDefined();
      expect(defs["Reading"]).toBeDefined();
    });

    it("compiles offline and accepts the upstream example subject", () => {
      const result = validator.validateCredentialSubject(
        "ies/meter-data-credential/v0.6",
        validMeterDataSubject,
      );
      expect(result.errors).toEqual([]);
      expect(result.valid).toBe(true);
    });

    it("rejects a subject missing meterData", () => {
      const result = validator.validateCredentialSubject("ies/meter-data-credential/v0.6", {
        id: "did:dedi:bescom:consumers:RR-1234",
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.field === "meterData")).toBe(true);
    });

    it("rejects a subject whose meterData does not match the payload schema", () => {
      const result = validator.validateCredentialSubject("ies/meter-data-credential/v0.6", {
        meterData: { bogus: true },
      });
      expect(result.valid).toBe(false);
    });
  });
});
