import { describe, it, expect } from "vitest";
import { generateInlineContext } from "../context-generator.js";

const XSD = "http://www.w3.org/2001/XMLSchema#";

describe("generateInlineContext", () => {
  it("maps plain string fields to short form", () => {
    const schema = {
      type: "object",
      properties: {
        name: { type: "string" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx.name).toBe("https://example.com/ns#name");
  });

  it("maps date format to xsd:date", () => {
    const schema = {
      type: "object",
      properties: {
        issued: { type: "string", format: "date" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx.issued).toEqual({
      "@id": "https://example.com/ns#issued",
      "@type": `${XSD}date`,
    });
  });

  it("maps date-time format to xsd:dateTime", () => {
    const schema = {
      type: "object",
      properties: {
        timestamp: { type: "string", format: "date-time" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx.timestamp).toEqual({
      "@id": "https://example.com/ns#timestamp",
      "@type": `${XSD}dateTime`,
    });
  });

  it("maps uri/url format to @id type", () => {
    const schema = {
      type: "object",
      properties: {
        homepage: { type: "string", format: "uri" },
        website: { type: "string", format: "url" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx.homepage).toEqual({
      "@id": "https://example.com/ns#homepage",
      "@type": "@id",
    });
    expect(ctx.website).toEqual({
      "@id": "https://example.com/ns#website",
      "@type": "@id",
    });
  });

  it("maps email format to short form (no @type)", () => {
    const schema = {
      type: "object",
      properties: {
        email: { type: "string", format: "email" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx.email).toBe("https://example.com/ns#email");
  });

  it("maps number to xsd:double", () => {
    const schema = {
      type: "object",
      properties: {
        score: { type: "number" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx.score).toEqual({
      "@id": "https://example.com/ns#score",
      "@type": `${XSD}double`,
    });
  });

  it("maps integer to xsd:integer", () => {
    const schema = {
      type: "object",
      properties: {
        count: { type: "integer" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx.count).toEqual({
      "@id": "https://example.com/ns#count",
      "@type": `${XSD}integer`,
    });
  });

  it("maps boolean to xsd:boolean", () => {
    const schema = {
      type: "object",
      properties: {
        active: { type: "boolean" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx.active).toEqual({
      "@id": "https://example.com/ns#active",
      "@type": `${XSD}boolean`,
    });
  });

  it("returns empty object for schema with no properties", () => {
    const schema = { type: "object" };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");
    expect(ctx).toEqual({});
  });

  it("correctly generates context for education schema", () => {
    const educationSchema = {
      type: "object",
      properties: {
        name: { type: "string" },
        degree: { type: "string" },
        institution: { type: "string" },
        dateConferred: { type: "string", format: "date" },
      },
    };
    const ns = "https://schema.nfh.global/vocab/education#";
    const ctx = generateInlineContext(educationSchema, ns);

    expect(ctx.name).toBe(`${ns}name`);
    expect(ctx.degree).toBe(`${ns}degree`);
    expect(ctx.institution).toBe(`${ns}institution`);
    expect(ctx.dateConferred).toEqual({
      "@id": `${ns}dateConferred`,
      "@type": `${XSD}date`,
    });
  });

  it("handles mixed types in a single schema", () => {
    const schema = {
      type: "object",
      properties: {
        label: { type: "string" },
        count: { type: "integer" },
        ratio: { type: "number" },
        active: { type: "boolean" },
        issued: { type: "string", format: "date" },
        link: { type: "string", format: "uri" },
      },
    };
    const ctx = generateInlineContext(schema, "https://example.com/ns#");

    // Plain string → short form
    expect(typeof ctx.label).toBe("string");
    // Typed fields → expanded form
    expect(ctx.count).toHaveProperty("@type");
    expect(ctx.ratio).toHaveProperty("@type");
    expect(ctx.active).toHaveProperty("@type");
    expect(ctx.issued).toHaveProperty("@type");
    expect(ctx.link).toHaveProperty("@type");
  });
});
