/**
 * DNS TXT record challenge verifier.
 *
 * Verifies domain ownership by checking for a specific TXT record
 * containing the challenge token. Uses multiple DNS resolvers to
 * mitigate cache poisoning attacks.
 *
 * Security considerations:
 * - Queries both the system default resolver and Google Public DNS (8.8.8.8)
 * - Both resolvers must confirm the record to pass verification
 * - Challenge tokens are never logged
 */

import dns from "node:dns";
import { AttestationError } from "@opencred/shared";

/** The prefix for OpenCred DNS TXT verification records. */
export const DNS_TXT_PREFIX = "opencred-verify=";

/**
 * Verify a DNS TXT challenge by querying for the expected token.
 *
 * Queries multiple DNS resolvers (system default + Google Public DNS)
 * to mitigate DNS cache poisoning attacks. The challenge is only
 * considered verified if ALL resolvers return the expected record.
 *
 * @param domain - The domain to query TXT records for
 * @param expectedToken - The challenge token expected in the TXT record
 * @returns true if the expected TXT record is found on all resolvers
 */
export async function verifyDnsTxtChallenge(
  domain: string,
  expectedToken: string,
): Promise<boolean> {
  if (!domain) {
    throw new AttestationError("Domain is required for DNS verification");
  }
  if (!expectedToken) {
    throw new AttestationError("Expected token is required for DNS verification");
  }

  const expectedValue = `${DNS_TXT_PREFIX}${expectedToken}`;

  // Query system default resolver
  const defaultResult = await queryDnsTxt(domain, expectedValue);

  // Query Google Public DNS (8.8.8.8) as a second resolver
  const googleResult = await queryDnsTxtWithResolver(domain, expectedValue, "8.8.8.8");

  // Both resolvers must confirm the record
  return defaultResult && googleResult;
}

/**
 * Query DNS TXT records using the system default resolver.
 */
async function queryDnsTxt(
  domain: string,
  expectedValue: string,
): Promise<boolean> {
  try {
    const records = await dns.promises.resolveTxt(domain);
    return matchesTxtRecord(records, expectedValue);
  } catch {
    return false;
  }
}

/**
 * Query DNS TXT records using a specific resolver address.
 */
async function queryDnsTxtWithResolver(
  domain: string,
  expectedValue: string,
  resolverAddress: string,
): Promise<boolean> {
  try {
    const resolver = new dns.Resolver();
    resolver.setServers([resolverAddress]);

    const records = await new Promise<string[][]>((resolve, reject) => {
      resolver.resolveTxt(domain, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses);
      });
    });

    return matchesTxtRecord(records, expectedValue);
  } catch {
    return false;
  }
}

/**
 * Check if any TXT record matches the expected value.
 * DNS TXT records are returned as arrays of strings (chunks)
 * that must be concatenated before comparison.
 */
function matchesTxtRecord(records: string[][], expectedValue: string): boolean {
  for (const record of records) {
    // TXT records may be split into chunks; concatenate them
    const joined = record.join("");
    if (joined === expectedValue) {
      return true;
    }
  }
  return false;
}
