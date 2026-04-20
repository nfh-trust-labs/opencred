/**
 * PFX/P12 file parser for DSC import.
 *
 * Extracts private keys, public keys, and certificate chains from
 * PKCS#12 (.pfx/.p12) files. Used by Type A issuers to import DSC
 * files that bundle the signing key with its certificate chain.
 *
 * SECURITY INVARIANTS:
 *  - Key material is NEVER logged — only fingerprints/IDs.
 *  - The parsed KeyObjects stay in memory and are never serialized.
 *  - Password is used only for decryption and not stored.
 */

import forge from "node-forge";
import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { CryptoError } from "@opencred/shared";
import { detectKeyAlgorithm, type SigningAlgorithm } from "@opencred/crypto";

export interface PfxContents {
  privateKey: KeyObject;
  publicKey: KeyObject;
  certificateChain: string[];
  keyAlgorithm: SigningAlgorithm;
}

/**
 * Parse a PFX/P12 buffer and extract key material and certificates.
 *
 * @param buffer - The raw PFX file content.
 * @param password - The password to decrypt the PFX.
 * @returns Parsed key material and certificate chain.
 * @throws {CryptoError} if the PFX is invalid, password is wrong, or key type is unsupported.
 */
export function parsePfx(buffer: Buffer, password: string): PfxContents {
  let asn1: forge.asn1.Asn1;
  try {
    const binaryString = buffer.toString("binary");
    asn1 = forge.asn1.fromDer(binaryString);
  } catch {
    throw new CryptoError("Invalid PFX data: failed to parse ASN.1 structure");
  }

  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);
  } catch {
    throw new CryptoError("Failed to decrypt PFX: wrong password or corrupted file");
  }

  // Extract private key
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBagList = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];

  if (!keyBagList || keyBagList.length === 0) {
    throw new CryptoError("PFX contains no private key");
  }

  const bag = keyBagList[0];
  let privateKey: KeyObject;

  if (bag.key) {
    // RSA: node-forge can parse the key natively
    const pem = forge.pki.privateKeyToPem(bag.key);
    try {
      privateKey = createPrivateKey(pem);
    } catch {
      throw new CryptoError("Failed to convert PFX private key to KeyObject");
    }
  } else if (bag.asn1) {
    // EC: node-forge cannot parse EC keys, but the decrypted PKCS#8
    // ASN.1 structure is available. Convert it to DER and let Node.js parse it.
    try {
      const derBytes = forge.asn1.toDer(bag.asn1);
      const derBuffer = Buffer.from(derBytes.getBytes(), "binary");
      privateKey = createPrivateKey({ key: derBuffer, format: "der", type: "pkcs8" });
    } catch {
      throw new CryptoError("Failed to extract private key from PFX");
    }
  } else {
    throw new CryptoError("Failed to extract private key from PFX");
  }

  const publicKey = createPublicKey(privateKey);

  // Detect algorithm from the Node.js KeyObject
  const keyAlgorithm = detectKeyAlgorithm(publicKey);

  // Extract certificate chain
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certBagList = certBags[forge.pki.oids.certBag];

  const certificateChain: string[] = [];
  if (certBagList) {
    for (const certBag of certBagList) {
      if (certBag.cert) {
        // RSA certs: forge can parse them natively
        certificateChain.push(forge.pki.certificateToPem(certBag.cert));
      } else if (certBag.asn1) {
        // EC certs: forge can't parse EC public keys, so convert raw ASN.1 to PEM
        const derBytes = forge.asn1.toDer(certBag.asn1);
        const derBuffer = Buffer.from(derBytes.getBytes(), "binary");
        const b64 = derBuffer.toString("base64");
        const lines = b64.match(/.{1,64}/g) || [];
        certificateChain.push(
          `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`,
        );
      }
    }
  }

  return {
    privateKey,
    publicKey,
    certificateChain,
    keyAlgorithm,
  };
}
