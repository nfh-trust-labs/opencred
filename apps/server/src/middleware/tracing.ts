/**
 * HTTP server tracing middleware for Hono.
 *
 * Wraps every request in a SERVER-kind span named after the method and
 * the **registered route pattern** (e.g. `POST /credentials/batch/:jobId/cancel`).
 * The raw URL is NEVER used because it would push cardinality through the
 * roof and could carry credential identifiers — see CLAUDE.md.
 *
 * SECURITY:
 *  - Authorization headers, request bodies, and query strings are never
 *    attached to the span.
 *  - URL path is **normalised** via the same regex as `metricsMiddleware`
 *    (UUIDs / long hex ids → `:id`). If Hono's `c.req.routePath` returned
 *    the pattern, we prefer that; otherwise we fall back to the
 *    normalised path. Pattern wins because it is the canonical
 *    operator-facing name.
 *
 *  - We deliberately do NOT propagate trace context from incoming
 *    headers right now: the server is the trace root for every
 *    OpenCred request. If a future deployment puts an upstream proxy
 *    that already emits traces, we can opt in by reading
 *    `traceparent` here — it's a one-line change. Leaving it off
 *    avoids the failure mode where a misconfigured upstream injects
 *    bogus trace ids that smear OpenCred spans across unrelated
 *    traces in Grafana.
 */

import type { Context, Next } from "hono";

import {
  runInSpan,
  SpanKind,
  SpanStatusCode,
} from "../observability/span-helpers.js";

/**
 * Normalise a raw URL path the same way `metricsMiddleware` does —
 * replace UUIDs and long hex segments with `:id` so high-cardinality
 * identifiers don't appear in span names.
 */
function normalisePath(raw: string): string {
  return raw
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "/:id")
    .replace(/\/[0-9a-f]{24,}/gi, "/:id");
}

/**
 * Resolve the canonical span name for a request.
 *
 * Priority:
 *   1. `c.req.routePath` — the pattern the route was registered with
 *      (e.g. `/credentials/batch/:jobId`). When mounted via
 *      `app.route("/v1", routes)`, Hono returns the **basePath** plus
 *      the registered pattern, which is exactly what we want.
 *   2. `c.req.path` after id-normalisation — fallback when the route
 *      didn't match any handler (404), so `routePath` is unset.
 */
function resolveRouteName(c: Context): string {
  const method = c.req.method;
  const routePath = c.req.routePath;
  // Hono returns "*" for catch-all middleware mounts; we want a real
  // pattern, so fall through to the normalised path in that case.
  if (routePath && routePath !== "*" && routePath !== "/*") {
    return `${method} ${routePath}`;
  }
  return `${method} ${normalisePath(c.req.path)}`;
}

export async function tracingMiddleware(c: Context, next: Next): Promise<void> {
  const method = c.req.method;
  const rawPath = c.req.path;
  const normalisedPath = normalisePath(rawPath);

  await runInSpan(
    `${method} ${normalisedPath}`,
    {
      "http.request.method": method,
      "http.route": normalisedPath,
      "url.scheme": c.req.url.startsWith("https") ? "https" : "http",
    },
    async (span) => {
      // `runInSpan` already records the exception + sets status from
      // any throw, so we don't wrap in a try/catch here. The middleware
      // does its own post-handler work AFTER `next()` returns, which
      // is the path Hono takes when the handler returns normally (or
      // when its error handler translated an exception into a body).
      await next();

      // After the handler runs, Hono has populated `c.req.routePath`
      // (and `c.res.status`). Rename the span to the **route pattern**
      // (e.g. `POST /credentials/batch/:jobId/cancel`) so traces line
      // up with the metrics dashboard's path labels.
      const finalName = resolveRouteName(c);
      span.updateName(finalName);
      const status = c.res.status;
      span.setAttribute("http.response.status_code", status);
      span.setAttribute("http.route", finalName.slice(method.length + 1));
      if (status >= 500) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: `HTTP ${status}` });
      }
    },
    { kind: SpanKind.SERVER },
  );
}
