/**
 * Schema listing endpoint.
 *
 * Returns the available credential schemas from the server-wide registry.
 */

import { Hono } from "hono";
import { getSchemaRegistry } from "../schema-registry-singleton.js";

const schemas = new Hono();

function getRegistry() {
  return getSchemaRegistry();
}

schemas.get("/schemas", (c) => {
  const reg = getRegistry();
  const schemaIds = reg.listSchemas();
  const schemaList = schemaIds.map((id: string) => {
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

export { schemas };
