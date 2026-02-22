import type { DIDResolutionResult } from "./types.js";

export interface DIDResolver {
  resolve(did: string): Promise<DIDResolutionResult>;
}
