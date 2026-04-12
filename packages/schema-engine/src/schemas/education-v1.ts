/**
 * Education Credential Schema (v1) — locally-defined schema.
 *
 * Follows the W3C VC Data Model 2.0 envelope pattern used by other
 * OpenCred-defined schemas (electricity, immunization, etc.).
 */

import { createHash } from "node:crypto";
import type { SchemaDefinition } from "../types.js";

export const educationV1Schema: Record<string, unknown> = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://opencred.org/schemas/education/v1/schema.json",
  title: "Education Credential",
  description:
    "W3C VC 2.0 envelope for an educational achievement credential, attesting that a recipient has been conferred a degree or qualification by an institution.",
  type: "object",
  required: [
    "@context",
    "id",
    "type",
    "issuer",
    "validFrom",
    "credentialSubject",
  ],
  properties: {
    "@context": {
      type: "array",
      items: { type: "string" },
      contains: { const: "https://www.w3.org/ns/credentials/v2" },
      minItems: 1,
    },
    id: {
      type: "string",
      format: "uri",
    },
    type: {
      type: "array",
      items: { type: "string" },
      contains: { const: "EducationCredential" },
      minItems: 2,
    },
    issuer: {
      oneOf: [
        { type: "string", format: "uri" },
        {
          type: "object",
          required: ["id"],
          properties: {
            id: { type: "string", format: "uri" },
            name: { type: "string" },
          },
        },
      ],
    },
    validFrom: { type: "string", format: "date-time" },
    validUntil: { type: "string", format: "date-time" },
    credentialStatus: {
      type: "object",
      properties: {
        id: { type: "string", format: "uri" },
        type: { type: "string" },
      },
    },
    credentialSubject: { $ref: "#/$defs/EducationSubject" },
    proof: {
      type: "object",
      properties: {
        type: { type: "string" },
        created: { type: "string", format: "date-time" },
        verificationMethod: { type: "string", format: "uri" },
        proofPurpose: { type: "string" },
        proofValue: { type: "string" },
      },
    },
  },
  $defs: {
    EducationSubject: {
      type: "object",
      required: ["recipientName", "degree", "institution", "dateConferred"],
      properties: {
        id: { type: "string", format: "uri" },
        recipientName: {
          type: "string",
          minLength: 1,
          description: "Full name of the degree recipient.",
        },
        degree: {
          type: "string",
          minLength: 1,
          description:
            "Name of the degree or qualification conferred (e.g. Bachelor of Science).",
        },
        institution: {
          type: "string",
          minLength: 1,
          description: "Name of the institution that conferred the degree.",
        },
        dateConferred: {
          type: "string",
          format: "date",
          description: "Date the degree was conferred (ISO 8601 date).",
        },
        fieldOfStudy: {
          type: "string",
          description: "Major, specialisation, or field of study.",
        },
        honours: {
          type: "string",
          description:
            "Honours classification (e.g. summa cum laude, First Class).",
        },
        gpa: {
          type: "number",
          minimum: 0,
          description: "Grade point average at graduation.",
        },
        accreditationBody: {
          type: "string",
          description:
            "Name of the accreditation body that recognises the programme.",
        },
        programDuration: {
          type: "string",
          description:
            "Duration of the programme (e.g. 4 years, 36 months).",
        },
        credentialNumber: {
          type: "string",
          description:
            "Unique credential or certificate number assigned by the institution.",
        },
      },
    },
  },
};

const canonical = JSON.stringify(educationV1Schema);
const educationV1Checksum = createHash("sha256")
  .update(canonical)
  .digest("hex");

export const educationV1Definition: SchemaDefinition = {
  id: "education/v1",
  schema: educationV1Schema,
  contextUrl: "urn:opencred:context:education:v1",
  version: "1.0.0",
  lastUpdated: "2026-04-12T00:00:00Z",
  checksum: educationV1Checksum,
  source: {
    kind: "defined",
    upstreamUrl: "https://opencred.org/schemas/education/v1/schema.json",
    upstreamOwner: "OpenCred",
    upstreamLicense: "MIT",
  },
  category: "education",
};
