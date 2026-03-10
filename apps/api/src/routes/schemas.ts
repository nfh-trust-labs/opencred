import { Hono } from "hono";
import type { SchemaRegistry } from "@opencred/schema-engine";
import { createRegistry } from "@opencred/schema-engine";
import { NotImplementedError } from "@opencred/shared";

export interface SchemaDeps {
  registry?: SchemaRegistry;
}

export function createSchemaRoutes(deps: SchemaDeps = {}) {
  const registry = deps.registry ?? createRegistry();
  const schemas = new Hono();

  // List all registered schemas
  schemas.get("/", (c) => {
    const ids = registry.listSchemas();
    const all = ids.map((id) => registry.getSchema(id));
    return c.json({ schemas: all });
  });

  // Retrieve a single schema by ID (throws NotFoundError → 404 via error handler)
  schemas.get("/:id", (c) => {
    const definition = registry.getSchema(c.req.param("id"));
    return c.json(definition);
  });

  // Custom schema registration — future work
  schemas.post("/", () => {
    throw new NotImplementedError("Custom schema registration is not yet implemented");
  });

  return schemas;
}
