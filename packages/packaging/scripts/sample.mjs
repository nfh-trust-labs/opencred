#!/usr/bin/env node
/**
 * sample.mjs — render a sample certificate PDF for eyeballing the design.
 *
 *   pnpm --filter @opencred/packaging build
 *   node packages/packaging/scripts/sample.mjs [out.pdf]
 *
 * Writes to packages/packaging/sample.pdf by default. Not shipped — a
 * design aid for reviewing layout changes to the generator.
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { generatePdf } from "../dist/index.js";

const credential = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: "urn:uuid:5f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
  type: ["VerifiableCredential", "UniversityDegreeCredential"],
  issuer: { id: "did:web:university.example", name: "Example University" },
  validFrom: "2025-06-01T00:00:00Z",
  validUntil: "2035-06-01T00:00:00Z",
  credentialSubject: {
    id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    name: "Ada Lovelace",
    degree: "Bachelor of Science",
    field: "Computer Science",
    graduationDate: "2025-05-20",
    honors: { distinction: "First Class", gpa: "3.92" },
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-rdfc-2019",
    created: "2025-06-01T12:00:00Z",
    verificationMethod: "did:web:university.example#key-1",
    proofPurpose: "assertionMethod",
    proofValue: "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoGgQXcEvHZGSm2",
  },
};

const out = process.argv[2]
  ? process.argv[2]
  : fileURLToPath(new URL("../sample.pdf", import.meta.url));

const buf = await generatePdf(credential, {
  customization: { issuerDisplayName: "Example University" },
});
writeFileSync(out, buf);
console.log(`Wrote ${out} (${buf.length} bytes)`);
