import { describe, it, expect } from "vitest";
import { getCategoryForSchema } from "../schema-categories.js";
import { createRegistry } from "../index.js";

describe("getCategoryForSchema", () => {
  it("maps education schemas", () => {
    expect(getCategoryForSchema("education/v1")).toBe("education");
    expect(getCategoryForSchema("open-badges/v3")).toBe("education");
  });

  it("maps employment schemas", () => {
    expect(getCategoryForSchema("employment-offer-letter/v1")).toBe("employment");
    expect(getCategoryForSchema("salary-slip/v1")).toBe("employment");
  });

  it("maps identity schemas", () => {
    expect(getCategoryForSchema("functional-identity/v1")).toBe("identity");
    expect(getCategoryForSchema("dif/verified-person/v1")).toBe("identity");
    expect(getCategoryForSchema("dif/proof-of-age/v1")).toBe("identity");
  });

  it("maps health schemas", () => {
    expect(getCategoryForSchema("immunization/v1")).toBe("health");
    expect(getCategoryForSchema("prescription/v1")).toBe("health");
    expect(getCategoryForSchema("test-result/v1")).toBe("health");
  });

  it("maps business schemas", () => {
    expect(getCategoryForSchema("business-entity/v1")).toBe("business");
    expect(getCategoryForSchema("insurance-policy/v1")).toBe("business");
  });

  it("maps utility schemas", () => {
    expect(getCategoryForSchema("electricity/v1")).toBe("utility");
  });

  it("maps traceability schemas via prefix", () => {
    expect(getCategoryForSchema("traceability/commercial-invoice/v1")).toBe("supply-chain");
    expect(getCategoryForSchema("traceability/bill-of-lading/v1")).toBe("supply-chain");
    expect(getCategoryForSchema("traceability/sbom/v1")).toBe("supply-chain");
    expect(getCategoryForSchema("traceability/freight-manifest/v1")).toBe("supply-chain");
  });

  it("returns 'other' for unknown schemas", () => {
    expect(getCategoryForSchema("unknown/v1")).toBe("other");
    expect(getCategoryForSchema("some-new-schema/v2")).toBe("other");
  });
});

describe("category assignment in registry", () => {
  it("every schema in the registry has a category", () => {
    const registry = createRegistry();
    for (const id of registry.listSchemas()) {
      const def = registry.getSchema(id);
      expect(def.category).toBeDefined();
      expect(def.category).not.toBe("");
    }
  });

  it("listSchemasByCategory groups all schemas", () => {
    const registry = createRegistry();
    const grouped = registry.listSchemasByCategory();
    const allIds = Object.values(grouped).flat().sort();
    const directIds = registry.listSchemas().sort();
    expect(allIds).toEqual(directIds);
  });
});
