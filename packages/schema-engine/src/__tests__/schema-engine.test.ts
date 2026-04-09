import { describe, it, expect, beforeEach } from "vitest";
import { NotFoundError } from "@opencred/shared";
import { SchemaRegistry } from "../schema-registry.js";
import { Validator } from "../validator.js";
import { createRegistry } from "../index.js";
import type { SchemaDefinition } from "../types.js";

function makeDef(overrides: Partial<SchemaDefinition> = {}): SchemaDefinition {
  return {
    id: "test",
    schema: { type: "object", properties: { name: { type: "string" } } },
    version: "1.0.0",
    lastUpdated: "2026-04-08T00:00:00Z",
    checksum: "0".repeat(64),
    source: {
      kind: "defined",
      upstreamUrl: "https://example.invalid/test/v1",
      upstreamOwner: "OpenCred",
      upstreamLicense: "Apache-2.0",
    },
    ...overrides,
  };
}

describe("SchemaRegistry", () => {
  let registry: SchemaRegistry;

  beforeEach(() => {
    registry = new SchemaRegistry();
  });

  it("registers and retrieves a schema", () => {
    const def = makeDef({ id: "alpha" });
    registry.register(def);
    const result = registry.getSchema("alpha");
    expect(result.id).toBe("alpha");
    expect(result.schema).toBe(def.schema);
  });

  it("throws NotFoundError for unknown schema", () => {
    expect(() => registry.getSchema("unknown")).toThrow(NotFoundError);
  });

  it("lists all registered schema IDs", () => {
    registry.register(makeDef({ id: "a" }));
    registry.register(makeDef({ id: "b" }));
    registry.register(makeDef({ id: "c" }));
    expect(registry.listSchemas()).toEqual(["a", "b", "c"]);
  });

  it("maps id to context URL when contextUrl is set", () => {
    registry.register(makeDef({ id: "withctx", contextUrl: "https://example.invalid/withctx/v1" }));
    expect(registry.getContextForType("withctx")).toBe("https://example.invalid/withctx/v1");
  });

  it("returns undefined for unmapped id", () => {
    expect(registry.getContextForType("unknown")).toBeUndefined();
  });

  it("computeChecksum returns a stable SHA-256 hex digest (legacy helper)", () => {
    const a = SchemaRegistry.computeChecksum({ type: "object" });
    const b = SchemaRegistry.computeChecksum({ type: "object" });
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("getManifest returns ids/versions/checksums from registered schemas", () => {
    registry.register(makeDef({ id: "alpha", version: "1.2.3", checksum: "a".repeat(64) }));
    registry.register(makeDef({ id: "beta", version: "2.0.0", checksum: "b".repeat(64) }));
    const manifest = registry.getManifest();
    expect(manifest.schemas).toEqual([
      { id: "alpha", version: "1.2.3", checksum: "a".repeat(64) },
      { id: "beta", version: "2.0.0", checksum: "b".repeat(64) },
    ]);
  });
});

describe("createRegistry (built-in)", () => {
  // The built-in registry is populated at build time by
  // scripts/fetch-and-embed-schemas.mjs. The placeholder generated-registry.ts
  // committed in this PR registers zero schemas; once Stream A's manifest
  // exists and the build script runs, this snapshot will lock in the full
  // catalogue. The shape assertions below intentionally tolerate the empty
  // pre-build state and only verify the contract.
  it("returns a SchemaRegistry instance", () => {
    const registry = createRegistry();
    expect(registry).toBeInstanceOf(SchemaRegistry);
  });

  it("every registered schema satisfies the SchemaDefinition contract", () => {
    const registry = createRegistry();
    for (const id of registry.listSchemas()) {
      const def = registry.getSchema(id);
      expect(def.id).toBe(id);
      expect(def.schema).toBeTypeOf("object");
      expect(def.version).toMatch(/^\d+\.\d+\.\d+$/);
      expect(def.lastUpdated).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(def.checksum).toMatch(/^[0-9a-f]{64}$/);
      expect(def.source.kind).toMatch(/^(defined|referenced)$/);
      expect(def.source.upstreamUrl).toBeTypeOf("string");
      expect(def.source.upstreamOwner).toBeTypeOf("string");
      expect(def.source.upstreamLicense).toBeTypeOf("string");
    }
  });

  it("registry id list is stable (snapshot)", () => {
    const registry = createRegistry();
    expect(registry.listSchemas().sort()).toMatchSnapshot();
  });
});

describe("Validator", () => {
  let validator: Validator;
  let registry: SchemaRegistry;

  beforeEach(() => {
    registry = new SchemaRegistry();
    registry.register(
      makeDef({
        id: "custom",
        schema: {
          type: "object",
          required: ["foo"],
          properties: { foo: { type: "number" } },
          additionalProperties: false,
        },
      }),
    );
    validator = new Validator(registry);
  });

  it("validates against a registered schema", () => {
    expect(validator.validateCredentialSubject("custom", { foo: 42 }).valid).toBe(true);
    expect(validator.validateCredentialSubject("custom", { foo: "x" }).valid).toBe(false);
    expect(validator.validateCredentialSubject("custom", {}).valid).toBe(false);
  });

  it("validateOrThrow throws on invalid input", () => {
    expect(() => validator.validateOrThrow("custom", { foo: "x" })).toThrow();
  });
});
