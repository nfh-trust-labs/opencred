import type { DeDiClient } from "@opencred/dedi-client";
import { computeRevocationHash } from "@opencred/crypto";
import type { VerificationCheck } from "./types.js";

/**
 * Check validFrom / validUntil date constraints.
 * Returns a check result indicating whether the credential is within its validity period.
 */
export function checkDates(
  validFrom?: string,
  validUntil?: string,
  now: Date = new Date(),
): VerificationCheck {
  if (validFrom) {
    const from = new Date(validFrom);
    if (isNaN(from.getTime())) {
      return { name: "date", passed: false, detail: "Invalid validFrom date" };
    }
    if (now < from) {
      return {
        name: "date",
        passed: false,
        detail: `Credential not yet valid (validFrom: ${validFrom})`,
      };
    }
  }

  if (validUntil) {
    const until = new Date(validUntil);
    if (isNaN(until.getTime())) {
      return { name: "date", passed: false, detail: "Invalid validUntil date" };
    }
    if (now > until) {
      return {
        name: "date",
        passed: false,
        detail: `Credential expired (validUntil: ${validUntil})`,
      };
    }
  }

  return { name: "date", passed: true };
}

/**
 * Check revocation status via DeDi registry.
 * Computes the JCS-canonical SHA-256 hash of the credential and queries DeDi.
 */
export async function checkRevocation(
  credential: unknown,
  dediClient: DeDiClient,
): Promise<VerificationCheck> {
  try {
    const hash = computeRevocationHash(credential);
    const record = await dediClient.queryRevocationHash(hash);
    if (record.revoked) {
      return {
        name: "revocation",
        passed: false,
        detail: `Credential revoked${record.revokedAt ? ` at ${record.revokedAt}` : ""}`,
      };
    }
    return { name: "revocation", passed: true };
  } catch {
    return {
      name: "revocation",
      passed: false,
      detail: "Unable to check revocation status: DeDi service unavailable",
    };
  }
}

/**
 * Check BitstringStatusList when credentialStatus.type is BitstringStatusListEntry.
 * Fetches the status list and checks the bit at the given index.
 */
export async function checkBitstringStatusList(
  credentialStatus: Record<string, unknown>,
): Promise<VerificationCheck> {
  try {
    const statusListIndex = credentialStatus["statusListIndex"];
    const statusListCredential = credentialStatus["statusListCredential"];

    if (statusListIndex === undefined || statusListCredential === undefined) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Missing statusListIndex or statusListCredential in credentialStatus",
      };
    }

    const index = Number(statusListIndex);
    if (!Number.isInteger(index) || index < 0) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Invalid statusListIndex: ${String(statusListIndex)}`,
      };
    }

    const response = await globalThis.fetch(String(statusListCredential));
    if (!response.ok) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Failed to fetch status list: HTTP ${response.status}`,
      };
    }

    const statusListVC = (await response.json()) as Record<string, unknown>;
    const subject = statusListVC["credentialSubject"] as Record<string, unknown> | undefined;
    if (!subject) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Status list credential missing credentialSubject",
      };
    }

    const encodedList = subject["encodedList"] as string | undefined;
    if (!encodedList) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Status list credential missing encodedList",
      };
    }

    // Decode the base64-encoded, GZIP-compressed bitstring
    const compressed = Buffer.from(encodedList, "base64");
    const { gunzipSync } = await import("node:zlib");
    const bitstring = gunzipSync(compressed);

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    if (byteIndex >= bitstring.length) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `statusListIndex ${index} out of range`,
      };
    }

    // Bits are MSB-first within each byte
    const isRevoked = (bitstring[byteIndex] & (0x80 >> bitIndex)) !== 0;

    if (isRevoked) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Credential revoked (statusListIndex: ${index})`,
      };
    }

    return { name: "bitstringStatus", passed: true };
  } catch {
    return {
      name: "bitstringStatus",
      passed: false,
      detail: "Unable to check BitstringStatusList",
    };
  }
}
