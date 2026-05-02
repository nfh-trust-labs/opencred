/**
 * Schema listing endpoint.
 *
 * Returns the available credential schemas from the server-wide registry.
 */

import { Hono } from "hono";
import { z } from "zod";
import { generateSchemaFromFields } from "@opencred/schema-engine";
import type { SchemaCategory } from "@opencred/schema-engine";
import { getSchemaRegistry } from "../schema-registry-singleton.js";
import { parseJsonBody } from "../middleware/parse-json.js";

const schemas = new Hono();

function getRegistry() {
  return getSchemaRegistry();
}

schemas.get("/schemas", (c) => {
  const reg = getRegistry();
  const categoryFilter = c.req.query("category") as SchemaCategory | undefined;

  const schemaIds = reg.listSchemas();
  const schemaList = schemaIds
    .map((id: string) => {
      const def = reg.getSchema(id);
      return {
        id: def.id,
        version: def.version,
        contextUrl: def.contextUrl,
        source: def.source,
        category: def.category,
      };
    })
    .filter((s) => !categoryFilter || s.category === categoryFilter);

  return c.json({ schemas: schemaList });
});

// Schema IDs in the v1 catalogue contain slashes (e.g. "functional-identity/v1",
// "traceability/commercial-invoice/v1", "dif/verified-person/v1"). Hono's
// default `:id` param does not match across `/`, so we use a regex param
// (`{.+}`) that captures the rest of the path.
schemas.get("/schemas/:id{.+}", (c) => {
  const reg = getRegistry();
  const id = c.req.param("id");

  try {
    const def = reg.getSchema(id);
    return c.json({
      id: def.id,
      version: def.version,
      schema: def.schema,
      contextUrl: def.contextUrl,
      source: def.source,
      category: def.category,
    });
  } catch {
    return c.json({ error: { code: "NOT_FOUND", message: `Schema not found: ${id}` } }, 404);
  }
});

const generateSchema = z.object({
  fields: z.record(z.unknown()),
});

schemas.post("/schemas/generate", async (c) => {
  // Malformed-body 400 is now emitted by `parseJsonBody` as INVALID_JSON
  // (small UX improvement over the previous VALIDATION_ERROR fallback).
  const body = await parseJsonBody(c);
  const parsed = generateSchema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "Body must include a fields object",
          details: parsed.error.flatten(),
        },
      },
      400,
    );
  }
  const result = generateSchemaFromFields(parsed.data.fields);
  return c.json({ schema: result.schema, fields: result.fields });
});

export { schemas };
