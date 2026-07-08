/**
 * Composite DID resolver — routes resolve() calls to the correct
 * sub-resolver based on the DID method prefix.
 *
 * Supports any combination of DID methods by accepting a map of
 * method name → resolver at construction time.
 */

import { DIDResolutionError } from "@opencred/shared";
import type { DIDResolutionResult } from "./types.js";
import type { DIDResolver } from "./resolver.js";

/**
 * A DID resolver that dispatches to method-specific sub-resolvers.
 *
 * @example
 * const resolver = new CompositeDIDResolver(new Map([
 *   ["key", new DIDKeyResolver()],
 *   ["jwk", new DIDJwkResolver()],
 *   ["web", new DIDWebResolver()],
 * ]));
 *
 * // Routes to DIDKeyResolver
 * await resolver.resolve("did:key:z6Mk...");
 *
 * // Routes to DIDWebResolver
 * await resolver.resolve("did:web:example.com");
 */
export class CompositeDIDResolver implements DIDResolver {
  private readonly resolvers: Map<string, DIDResolver>;

  constructor(resolvers: Map<string, DIDResolver>) {
    this.resolvers = resolvers;
  }

  async resolve(did: string): Promise<DIDResolutionResult> {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }

    const parts = did.split(":");
    if (parts.length < 3 || parts[0] !== "did") {
      throw new DIDResolutionError("Invalid DID format: expected did:<method>:<id>");
    }

    const method = parts[1];
    const resolver = this.resolvers.get(method);
    if (!resolver) {
      throw new DIDResolutionError(`No resolver registered for DID method: ${method}`);
    }

    return resolver.resolve(did);
  }
}
