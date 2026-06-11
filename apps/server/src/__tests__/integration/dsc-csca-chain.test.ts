import { describe, it, expect } from "vitest";
import { generateKeyPairSync, X509Certificate } from "node:crypto";
import forge from "node-forge";
import { signCredential } from "@opencred/crypto";
import type { UnsignedCredential } from "@opencred/vc-core";
import { verifyCredential, checkX509Chain } from "@opencred/verification";
import type {
  JWK,
  DIDResolver,
  DIDResolutionResult,
  DIDDocument,
  VerificationMethod,
} from "@opencred/did";

interface CertBundle {
  pem: string;
  derBase64: string;
  forgeKeys: forge.pki.rsa.KeyPair;
  jwk: JWK;
}

function generateCert(
  opts: { commonName: string; isCa?: boolean; serial?: string },
  issuer?: { keys: forge.pki.rsa.KeyPair; commonName: string },
): CertBundle {
  const forgeKeys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forgeKeys.publicKey;
  cert.serialNumber = opts.serial ?? "01";
  cert.validity.notBefore = new Date(Date.now() - 1000 * 60 * 60 * 24);
  cert.validity.notAfter = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365);

  const subject = [
    { shortName: "CN", value: opts.commonName },
    { shortName: "O", value: "Integration Test Org" },
    { shortName: "C", value: "US" },
  ];
  cert.setSubject(subject);
  cert.setIssuer(
    issuer
      ? [
          { shortName: "CN", value: issuer.commonName },
          { shortName: "O", value: "Integration Test Org" },
          { shortName: "C", value: "US" },
        ]
      : subject,
  );

  const extensions: Array<Record<string, unknown>> = [];
  if (opts.isCa) {
    extensions.push({ name: "basicConstraints", cA: true });
    extensions.push({ name: "keyUsage", keyCertSign: true, digitalSignature: true, cRLSign: true });
  } else {
    extensions.push({ name: "basicConstraints", cA: false });
    extensions.push({ name: "keyUsage", digitalSignature: true, keyEncipherment: true });
  }
  cert.setExtensions(extensions);

  cert.sign(issuer?.keys.privateKey ?? forgeKeys.privateKey, forge.md.sha256.create());

  const pem = forge.pki.certificateToPem(cert);
  const x509 = new X509Certificate(pem);
  const jwk = x509.publicKey.export({ format: "jwk" }) as JWK;
  const derBase64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s+/g, "");

  return { pem, derBase64, forgeKeys, jwk };
}

function makeResolver(did: string, vmId: string, jwk: JWK): DIDResolver {
  const vm: VerificationMethod = {
    id: vmId,
    type: "JsonWebKey",
    controller: did,
    publicKeyJwk: jwk,
  };
  return {
    resolve: async (input: string): Promise<DIDResolutionResult> => {
      if (input !== did) {
        return {
          didDocument: null,
          didResolutionMetadata: { error: "notFound" },
          didDocumentMetadata: {},
        };
      }
      return {
        didDocument: {
          "@context": "https://www.w3.org/ns/did/v1",
          id: did,
          verificationMethod: [vm],
          assertionMethod: [vmId],
        } as DIDDocument,
        didResolutionMetadata: {},
        didDocumentMetadata: {},
      };
    },
  };
}

function buildCredential(args: {
  x5c?: string[];
  verificationMethod?: string;
  created?: string;
}): Record<string, unknown> {
  const proof: Record<string, unknown> = {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: args.created ?? new Date().toISOString(),
  };
  if (args.x5c) proof["x5c"] = args.x5c;
  if (args.verificationMethod !== undefined) {
    proof["verificationMethod"] = args.verificationMethod;
  }
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:integration-chain-test",
    type: ["VerifiableCredential"],
    issuer: "did:web:integration.example",
    credentialSubject: { id: "did:example:holder" },
    proof,
  };
}

describe("X.509 DSC-CSCA trust chain (cross-package integration)", () => {
  const did = "did:web:integration.example";
  const vmId = `${did}#key-0`;

  const csca = generateCert({ commonName: "Integration CSCA Root", isCa: true });
  const dsc = generateCert(
    { commonName: "Integration DSC Leaf", serial: "02" },
    { keys: csca.forgeKeys, commonName: "Integration CSCA Root" },
  );

  it("valid chain: CSCA root -> DSC leaf with trust anchor -> chain check passes", async () => {
    const credential = buildCredential({
      x5c: [dsc.derBase64, csca.derBase64],
      verificationMethod: vmId,
    });

    const result = await checkX509Chain(credential, {
      didResolver: makeResolver(did, vmId, dsc.jwk),
      trustAnchors: [csca.pem],
    });

    expect(result.passed).toBe(true);
    expect(result.detail).toContain("DSC verified");
    expect(result.detail).toContain("anchored to");
  });

  it("no trust anchor: x5c present but trustAnchors omitted -> chain check fails", async () => {
    const credential = buildCredential({
      x5c: [dsc.derBase64, csca.derBase64],
      verificationMethod: vmId,
    });

    const result = await checkX509Chain(credential, {
      didResolver: makeResolver(did, vmId, dsc.jwk),
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("requires a configured trust anchor");
  });

  it("wrong CSCA: DSC signed by untrusted CSCA -> chain check fails", async () => {
    const untrustedCsca = generateCert({ commonName: "Untrusted CSCA", isCa: true });
    const credential = buildCredential({
      x5c: [dsc.derBase64, csca.derBase64],
      verificationMethod: vmId,
    });

    const result = await checkX509Chain(credential, {
      didResolver: makeResolver(did, vmId, dsc.jwk),
      trustAnchors: [untrustedCsca.pem],
    });

    expect(result.passed).toBe(false);
    expect(result.detail).toContain("does not terminate at a configured trust anchor");
  });

  it("no x5c: credential without x5c chain -> verifyCredential passes (chain check skipped)", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const ecJwk = publicKey.export({ format: "jwk" }) as JWK;

    const unsignedVC: UnsignedCredential = {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:integration-no-x5c-test",
      type: ["VerifiableCredential"],
      issuer: did,
      validFrom: new Date().toISOString(),
      credentialSubject: { id: "did:example:holder", name: "No-x5c Subject" },
    };

    const signedVC = await signCredential(
      unsignedVC,
      { id: vmId, privateKey, publicKey, algorithm: "P-256" },
      { verificationMethod: vmId, proofPurpose: "assertionMethod" },
    );

    const result = await verifyCredential(signedVC as unknown as Record<string, unknown>, {
      didResolver: makeResolver(did, vmId, ecJwk),
    });

    expect(result.verified).toBe(true);
    expect(result.code).toBe("VALID");
    const x509Check = result.checks.find((c) => c.name === "x509-chain");
    expect(x509Check).toBeDefined();
    expect(x509Check?.passed).toBe(true);
    expect(x509Check?.detail).toContain("not a DSC-backed credential");
  });
});
