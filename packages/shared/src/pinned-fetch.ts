/**
 * DNS-rebinding-safe HTTPS GET.
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

export interface PinnedFetchOptions {
  /** Request headers. */
  headers?: Record<string, string>;
  /** Abort signal — aborting rejects the promise with an `AbortError`. */
  signal?: AbortSignal;
}

/** Statuses for which the Response constructor forbids a body. */
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

/**
 * Perform an HTTPS GET that can only connect to `pinnedAddresses`.
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
 *   socket is allowed to connect to.
 * @param options - Headers and abort signal.
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

  return await new Promise<Response>((resolve, reject) => {
    const req = request(
      parsed,
      {
        method: "GET",
        agent,
        headers: options.headers,
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
    req.end();
  });
}
