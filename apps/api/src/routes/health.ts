import { Hono } from "hono";
import type { DeDiClient } from "@opencred/dedi-client";

export interface HealthDeps {
  dediClient?: DeDiClient;
}

export function createHealthRoutes(deps: HealthDeps = {}) {
  const healthRouter = new Hono();

  // Liveness probe — always responds OK if the process is running
  healthRouter.get("/health", (c) => {
    return c.json({
      status: "ok",
      timestamp: new Date().toISOString(),
    });
  });

  // Readiness probe — checks dependency connectivity
  healthRouter.get("/health/ready", async (c) => {
    const checks: Record<string, { status: "ok" | "unavailable"; detail?: string }> = {};

    if (deps.dediClient) {
      try {
        await deps.dediClient.apiClient.getStats();
        checks.dedi = { status: "ok" };
      } catch (err) {
        checks.dedi = {
          status: "unavailable",
          detail: err instanceof Error ? err.message : "DeDi connectivity check failed",
        };
      }
    }

    const allOk = Object.values(checks).every((ch) => ch.status === "ok");
    const status = allOk ? "ready" : "degraded";
    const statusCode = allOk ? 200 : 503;

    return c.json({ status, timestamp: new Date().toISOString(), checks }, statusCode);
  });

  return healthRouter;
}

// Backwards-compatible default export for liveness-only usage
const health = createHealthRoutes();
export { health };
