const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const ALPHABET_MAP = new Map<string, number>();
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  ALPHABET_MAP.set(BASE58_ALPHABET[i], i);
}

export function decodeBase58btc(encoded: string): Uint8Array {
  if (encoded.length === 0) {
    return new Uint8Array(0);
  }

  let leadingZeros = 0;
  for (const char of encoded) {
    if (char === "1") leadingZeros++;
    else break;
  }

  const size = Math.ceil(encoded.length * (Math.log(58) / Math.log(256)));
  const bytes = new Uint8Array(size);

  for (const char of encoded) {
    const value = ALPHABET_MAP.get(char);
    if (value === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    let carry = value;
    for (let j = size - 1; j >= 0; j--) {
      carry += 58 * bytes[j];
      bytes[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }
  }

  let firstNonZero = 0;
  while (firstNonZero < bytes.length && bytes[firstNonZero] === 0) {
    firstNonZero++;
  }

  const result = new Uint8Array(leadingZeros + (bytes.length - firstNonZero));
  result.set(bytes.subarray(firstNonZero), leadingZeros);
  return result;
}

export function encodeBase58btc(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return "";
  }

  let leadingZeros = 0;
  for (const byte of bytes) {
    if (byte === 0) leadingZeros++;
    else break;
  }

  const size = Math.ceil(bytes.length * (Math.log(256) / Math.log(58)));
  const digits = new Uint8Array(size);

  for (const byte of bytes) {
    let carry = byte;
    for (let j = size - 1; j >= 0; j--) {
      carry += 256 * digits[j];
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
  }

  let firstNonZero = 0;
  while (firstNonZero < digits.length && digits[firstNonZero] === 0) {
    firstNonZero++;
  }

  let result = "1".repeat(leadingZeros);
  for (let i = firstNonZero; i < digits.length; i++) {
    result += BASE58_ALPHABET[digits[i]];
  }

  return result;
}
