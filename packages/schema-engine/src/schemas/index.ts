export const educationSchema = {
  $id: "https://opencred.dev/schemas/education/v1",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Education Credential",
  type: "object",
  required: ["name", "degree", "institution", "dateConferred"],
  properties: {
    name: { type: "string", minLength: 1 },
    degree: { type: "string", minLength: 1 },
    institution: { type: "string", minLength: 1 },
    dateConferred: { type: "string", format: "date" },
  },
  additionalProperties: true,
} as const;

export const employmentSchema = {
  $id: "https://opencred.dev/schemas/employment/v1",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Employment Credential",
  type: "object",
  required: ["name", "employer", "position", "startDate"],
  properties: {
    name: { type: "string", minLength: 1 },
    employer: { type: "string", minLength: 1 },
    position: { type: "string", minLength: 1 },
    startDate: { type: "string", format: "date" },
  },
  additionalProperties: true,
} as const;

export const identitySchema = {
  $id: "https://opencred.dev/schemas/identity/v1",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Identity Credential",
  type: "object",
  required: ["name", "dateOfBirth", "nationality", "documentNumber"],
  properties: {
    name: { type: "string", minLength: 1 },
    dateOfBirth: { type: "string", format: "date" },
    nationality: { type: "string", minLength: 1 },
    documentNumber: { type: "string", minLength: 1 },
  },
  additionalProperties: true,
} as const;

// NOTE: `validUntil` is intentionally NOT a credentialSubject property here.
// The certification expiry IS the credential expiry — they are the same date,
// and modeling them separately invited collisions with the W3C credentials-v2
// VC-level `validUntil`.  Health credentials should set `validUntil` on the
// credential itself (via the existing UI field) instead of on the subject.
export const healthSchema = {
  $id: "https://opencred.dev/schemas/health/v1",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Health Credential",
  type: "object",
  required: ["name", "certification", "issuingBody"],
  properties: {
    name: { type: "string", minLength: 1 },
    certification: { type: "string", minLength: 1 },
    issuingBody: { type: "string", minLength: 1 },
  },
  additionalProperties: true,
} as const;

export const businessSchema = {
  $id: "https://opencred.dev/schemas/business/v1",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Business Credential",
  type: "object",
  required: ["name", "registrationNumber", "jurisdiction", "incorporationDate"],
  properties: {
    name: { type: "string", minLength: 1 },
    registrationNumber: { type: "string", minLength: 1 },
    jurisdiction: { type: "string", minLength: 1 },
    incorporationDate: { type: "string", format: "date" },
  },
  additionalProperties: true,
} as const;
