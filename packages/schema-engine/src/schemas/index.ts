/**
 * Built-in JSON Schemas for OpenCred credentials.
 *
 * The canonical schema definitions live in the `opencred-vc-schemas` repo:
 *   https://github.com/nfh-trust-labs/opencred-vc-schemas
 *
 * Each schema's `$id` points at its raw URL on that repo. We bundle the
 * schemas locally (no runtime fetching — see CLAUDE.md security invariant
 * #6) so issuance and validation work fully offline; the URL is only used
 * as the schema's stable identifier and as the value of `credentialSchema.id`
 * in issued credentials.
 *
 * Keep these in sync with `packages/schema-engine/src/schemas/*.json` and the
 * canonical schemas in opencred-vc-schemas. The JSON files exist for
 * downstream consumers that prefer to read schemas from disk; the TypeScript
 * exports below are what the schema engine actually uses at runtime.
 */

export const educationSchema = {
  $id: "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/education/v1/schema.json",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Education Credential",
  description:
    "Verifiable credential attesting that a person has been conferred an academic qualification by an institution.",
  type: "object",
  required: ["name", "degree", "institution", "dateConferred"],
  properties: {
    name: {
      type: "string",
      minLength: 1,
      description: "Full name of the person to whom the credential is issued.",
    },
    degree: {
      type: "string",
      minLength: 1,
      description:
        'The academic qualification conferred (e.g. "Bachelor of Science in Computer Science").',
    },
    institution: {
      type: "string",
      minLength: 1,
      description: "Legal name of the institution that conferred the qualification.",
    },
    dateConferred: {
      type: "string",
      format: "date",
      description: "ISO 8601 date (YYYY-MM-DD) on which the qualification was conferred.",
    },
  },
  additionalProperties: true,
} as const;

export const employmentSchema = {
  $id: "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/employment/v1/schema.json",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Employment Credential",
  description:
    "Verifiable credential attesting that a person holds (or held) a position at an organization.",
  type: "object",
  required: ["name", "employer", "position", "startDate"],
  properties: {
    name: {
      type: "string",
      minLength: 1,
      description: "Full name of the employee.",
    },
    employer: {
      type: "string",
      minLength: 1,
      description: "Legal name of the employing organization.",
    },
    position: {
      type: "string",
      minLength: 1,
      description: "Job title or role held by the employee.",
    },
    startDate: {
      type: "string",
      format: "date",
      description: "ISO 8601 date (YYYY-MM-DD) on which the employment began.",
    },
    endDate: {
      type: "string",
      format: "date",
      description:
        "ISO 8601 date (YYYY-MM-DD) on which the employment ended. Omit if employment is current.",
    },
  },
  additionalProperties: true,
} as const;

export const identitySchema = {
  $id: "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/identity/v1/schema.json",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Identity Credential",
  description:
    "Verifiable credential attesting basic identity attributes of a person, anchored to a government-issued document.",
  type: "object",
  required: ["name", "dateOfBirth", "nationality", "documentNumber"],
  properties: {
    name: {
      type: "string",
      minLength: 1,
      description: "Full legal name of the person.",
    },
    dateOfBirth: {
      type: "string",
      format: "date",
      description: "ISO 8601 date of birth (YYYY-MM-DD).",
    },
    nationality: {
      type: "string",
      minLength: 1,
      description:
        'Nationality, recommended as an ISO 3166-1 alpha-2 country code (e.g. "IN", "US").',
    },
    documentNumber: {
      type: "string",
      minLength: 1,
      description:
        "Identifier of the underlying government-issued document (passport, national ID, etc.).",
    },
  },
  additionalProperties: true,
} as const;

// NOTE: `validUntil` is intentionally NOT a credentialSubject property here.
// The certification expiry IS the credential expiry — they are the same date,
// and modeling them separately invited collisions with the W3C credentials-v2
// VC-level `validUntil`.  Health credentials should set `validUntil` on the
// credential itself (via the existing UI field) instead of on the subject.
export const healthSchema = {
  $id: "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/health/v1/schema.json",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Health Credential",
  description:
    "Verifiable credential attesting that a person holds a health-related certification (e.g. fitness-for-duty, professional medical certification).",
  type: "object",
  required: ["name", "certification", "issuingBody"],
  properties: {
    name: {
      type: "string",
      minLength: 1,
      description: "Full name of the credential subject.",
    },
    certification: {
      type: "string",
      minLength: 1,
      description: 'Name of the health certification (e.g. "Aviation Medical Class 1").',
    },
    issuingBody: {
      type: "string",
      minLength: 1,
      description: "Legal name of the body that issued the certification.",
    },
  },
  additionalProperties: true,
} as const;

export const businessSchema = {
  $id: "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/business/v1/schema.json",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Business Credential",
  description:
    "Verifiable credential attesting that an organization is incorporated in a particular jurisdiction under a specific registration number.",
  type: "object",
  required: ["name", "registrationNumber", "jurisdiction", "incorporationDate"],
  properties: {
    name: {
      type: "string",
      minLength: 1,
      description: "Legal name of the organization.",
    },
    registrationNumber: {
      type: "string",
      minLength: 1,
      description: "Registration number assigned by the registering authority.",
    },
    jurisdiction: {
      type: "string",
      minLength: 1,
      description:
        'Jurisdiction of incorporation, recommended as an ISO 3166-1 / ISO 3166-2 code (e.g. "IN", "US-DE").',
    },
    incorporationDate: {
      type: "string",
      format: "date",
      description: "ISO 8601 date (YYYY-MM-DD) on which the organization was incorporated.",
    },
  },
  additionalProperties: true,
} as const;
