/**
 * DNS-rebinding-safe HTTPS request.
 *
 * The SSRF pattern "validate the hostname's DNS, then `fetch(url)`" is a
 * TOCTOU hole: `fetch` re-resolves the hostname independently, so an
 * attacker-controlled DNS server can answer the validation query with a
 * public IP and the fetch-time query with a private one (cloud metadata,
 * localhost, ...). `fetchWithPinnedIp` closes that window by connecting the
 * socket directly to the addresses that were already validated.
 *
 * Why not put the IP in the URL and send a `Host` header? Because TLS
 * certificate validation runs against the URL host — `fetch("https://1.2.3.4/",
 * { headers: { Host: "example.com" } })` fails with
 * `ERR_TLS_CERT_ALTNAME_INVALID` on any host whose certificate lacks an IP
 * SAN (i.e. essentially all of them). Instead we keep the original hostname
 * in the request (correct SNI + certificate validation) and override the
 * socket-level DNS `lookup` so the connection can only go to a pinned,
 * pre-validated address.
 */

import { Agent, request } from "node:https";
import { isIP } from "node:net";
import { Readable } from "node:stream";
import type { LookupFunction } from "node:net";

/**
 * Anything the platform `Response` constructor accepts as a body — string,
 * `Uint8Array`, `Blob`, `FormData`, `URLSearchParams`, `ReadableStream`, … .
 * Derived from the global `Response` constructor rather than naming
 * `BodyInit`, which `@types/node` does not expose as a global type.
 */
export type PinnedFetchBody = NonNullable<ConstructorParameters<typeof Response>[0]>;

export interface PinnedFetchOptions {
  /** HTTP method. Defaults to `"GET"`. */
  method?: string;
  /** Request headers. */
  headers?: Record<string, string>;
  /**
   * Request body. Any body init (string, `Uint8Array`, `Blob`, `FormData`,
   * `URLSearchParams`, …). The body is normalized through the platform
   * `Response` constructor, so a `FormData` body gets a correct
   * `multipart/form-data; boundary=…` content type exactly as `fetch` would.
   * An explicit `Content-Type` in `headers` always wins.
   */
  body?: PinnedFetchBody | null;
  /** Abort signal — aborting rejects the promise with an `AbortError`. */
  signal?: AbortSignal;
}

/** Statuses for which the Response constructor forbids a body. */
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

/**
 * Normalize any body init to bytes plus the content type the platform would
 * have derived for it. Buffering (rather than streaming) lets us send an
 * accurate `Content-Length`, which is what `fetch` does for these body types
 * and what the widest range of receivers expect. Bodies on this path are
 * webhook payloads and DeDi API requests — small by construction.
 */
async function normalizeBody(body: PinnedFetchBody): Promise<{
  bytes: Buffer;
  contentType: string | null;
}> {
  const encoded = new Response(body);
  const bytes = Buffer.from(await encoded.arrayBuffer());
  return { bytes, contentType: encoded.headers.get("content-type") };
}

/** Case-insensitive header presence check. */
function hasHeader(headers: Record<string, string>, name: string): boolean {
  const wanted = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === wanted);
}

/**
 * Perform an HTTPS request that can only connect to `pinnedAddresses`.
 *
 * `pinnedAddresses` MUST be the output of an SSRF validation of the URL's
 * hostname (e.g. `resolveDnsForSsrf`) performed by the caller — this function
 * never consults DNS, which is exactly the point: no DNS query happens
 * between validation and connect, so a rebinding DNS server has nothing to
 * poison.
 *
 * Redirects are never followed (`https.request` does not follow redirects);
 * a 3xx surfaces as a non-ok `Response`, which callers already treat as an
 * HTTP error. This matches the `redirect: "error"` intent of the fetch calls
 * this helper replaces — a redirect must not be silently chased to a host
 * that was never SSRF-validated.
 *
 * @param url - The HTTPS URL to fetch. The hostname stays in the request so
 *   TLS SNI and certificate validation run against it.
 * @param pinnedAddresses - Pre-validated IP addresses (IPv4 and/or IPv6) the
 *   socket is allowed to connect to. Pass the FULL validated set, not just the
 *   first entry, so Node's happy-eyeballs failover still works for multi-A /
 *   dual-stack / CDN-fronted hosts.
 * @param options - Method, headers, body, and abort signal.
 * @returns A standard `Response` whose body streams from the socket.
 */
export async function fetchWithPinnedIp(
  url: string | URL,
  pinnedAddresses: readonly string[],
  options: PinnedFetchOptions = {},
): Promise<Response> {
  const parsed = typeof url === "string" ? new URL(url) : url;
  if (parsed.protocol !== "https:") {
    throw new Error("fetchWithPinnedIp requires an https: URL");
  }

  const entries = pinnedAddresses
    .map((address) => ({ address, family: isIP(address) }))
    .filter((entry) => entry.family !== 0);
  if (entries.length === 0) {
    throw new Error("fetchWithPinnedIp requires at least one valid pinned IP address");
  }

  // The pin: every socket this request opens resolves to a pre-validated
  // address. Node's happy-eyeballs path calls lookup with `all: true`; the
  // legacy path expects a single (address, family) pair — support both.
  const pinnedLookup: LookupFunction = (_hostname, lookupOptions, callback) => {
    if (lookupOptions.all) {
      callback(null, entries);
    } else {
      callback(null, entries[0].address, entries[0].family);
    }
  };

  // A dedicated, non-keep-alive agent per request. The global agent keeps a
  // process-wide socket pool keyed by host:port — a pooled socket would be
  // reused WITHOUT consulting `lookup`, silently bypassing the pin. A fresh
  // agent guarantees every request opens a new socket through pinnedLookup.
  const agent = new Agent({ keepAlive: false, lookup: pinnedLookup });

  // Normalize the body (if any) BEFORE opening the socket, and derive the
  // headers `fetch` would have set for it. An explicit caller-supplied
  // `Content-Type` always wins, matching fetch semantics.
  let payload: Buffer | undefined;
  let headers = options.headers;
  if (options.body !== undefined && options.body !== null) {
    const { bytes, contentType } = await normalizeBody(options.body);
    payload = bytes;
    headers = { ...options.headers };
    if (contentType !== null && !hasHeader(headers, "content-type")) {
      headers["Content-Type"] = contentType;
    }
    headers["Content-Length"] = String(bytes.byteLength);
  }

  return await new Promise<Response>((resolve, reject) => {
    const req = request(
      parsed,
      {
        method: options.method ?? "GET",
        agent,
        headers,
        signal: options.signal,
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const headers = new Headers();
        for (const [name, value] of Object.entries(res.headers)) {
          if (typeof value === "string") {
            headers.set(name, value);
          } else if (Array.isArray(value)) {
            for (const item of value) headers.append(name, item);
          }
        }
        const body = NULL_BODY_STATUSES.has(status) ? null : Readable.toWeb(res);
        try {
          resolve(
            new Response(body, {
              status,
              statusText: res.statusMessage ?? "",
              headers,
            }),
          );
        } catch (err) {
          res.destroy();
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      },
    );
    req.on("error", (err) => {
      reject(err);
    });
    if (payload !== undefined) {
      req.end(payload);
    } else {
      req.end();
    }
  });
}
