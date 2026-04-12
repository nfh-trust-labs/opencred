/**
 * Schema listing endpoint.
 *
 * Returns the available credential schemas from @opencred/schema-engine.
 */

import { Hono } from "hono";
import { createRegistry, generateSchemaFromFields } from "@opencred/schema-engine";

const schemas = new Hono();

// Singleton registry
let registry: ReturnType<typeof createRegistry> | null = null;

function getRegistry() {
  if (!registry) {
    registry = createRegistry();
  }
  return registry;
}

schemas.get("/schemas", (c) => {
  const reg = getRegistry();
  const schemaIds = reg.listSchemas();
  const schemaList = schemaIds.map((id) => {
    const def = reg.getSchema(id);
    return {
      id: def.id,
      version: def.version,
      contextUrl: def.contextUrl,
      source: def.source,
    };
  });

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
    });
  } catch {
    return c.json({ error: { code: "NOT_FOUND", message: `Schema not found: ${id}` } }, 404);
  }
});

schemas.post("/schemas/generate", async (c) => {
  const body = await c.req.json();
  if (!body.fields || typeof body.fields !== "object" || Array.isArray(body.fields)) {
    return c.json(
      { error: { code: "VALIDATION_ERROR", message: "Body must include a fields object" } },
      400,
    );
  }
  const result = generateSchemaFromFields(body.fields);
  return c.json({ schema: result.schema, fields: result.fields });
});

export { schemas };
