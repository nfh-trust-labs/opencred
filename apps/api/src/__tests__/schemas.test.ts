import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import type { SchemaDefinition } from "@opencred/schema-engine";
import { createSchemaRoutes } from "../routes/schemas.js";
import { errorHandler } from "../middleware/error-handler.js";
import { makeTestLogger } from "./helpers.js";

const logger = makeTestLogger();

function createTestApp() {
  const app = new Hono();
  app.route("/schemas", createSchemaRoutes());
  app.onError(errorHandler(logger));
  return app;
}

const BUILT_IN_IDS = ["education", "employment", "identity", "health", "business"];

describe("Schema routes", () => {
  const app = createTestApp();

  describe("GET /schemas", () => {
    it("returns 200 with all 5 built-in schemas", async () => {
      const res = await app.request("/schemas");
      expect(res.status).toBe(200);
      const body = (await res.json()) as { schemas: SchemaDefinition[] };
      expect(body.schemas).toHaveLength(5);
      const ids = body.schemas.map((s) => s.id);
      for (const id of BUILT_IN_IDS) {
        expect(ids).toContain(id);
      }
    });

    it("each schema has id, schema, and contextUrl", async () => {
      const res = await app.request("/schemas");
      const body = (await res.json()) as { schemas: SchemaDefinition[] };
      for (const def of body.schemas) {
        expect(def.id).toBeDefined();
        expect(typeof def.id).toBe("string");
        expect(def.schema).toBeDefined();
        expect(typeof def.schema).toBe("object");
        expect(def.contextUrl).toBeDefined();
        expect(typeof def.contextUrl).toBe("string");
      }
    });
  });

  describe("GET /schemas/:id", () => {
    it("returns 200 with the education schema", async () => {
      const res = await app.request("/schemas/education");
      expect(res.status).toBe(200);
      const body = (await res.json()) as SchemaDefinition;
      expect(body.id).toBe("education");
      expect(body.schema).toBeDefined();
      expect(body.contextUrl).toBe("https://opencred.dev/contexts/education/v1");
    });

    it("returns 404 for nonexistent schema", async () => {
      const res = await app.request("/schemas/nonexistent");
      expect(res.status).toBe(404);
      const body = (await res.json()) as { error: { code: string; message: string } };
      expect(body.error.code).toBe("NOT_FOUND");
    });
  });

  describe("POST /schemas", () => {
    it("returns 501 (custom registration not yet implemented)", async () => {
      const res = await app.request("/schemas", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      expect(res.status).toBe(501);
      const body = (await res.json()) as { error: { code: string; message: string } };
      expect(body.error.code).toBe("NOT_IMPLEMENTED");
    });
  });
});
