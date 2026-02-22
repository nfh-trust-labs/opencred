/**
 * Built-in credential schemas — mirrored from @opencred/schema-engine for browser use.
 * Each schema is a JSON Schema draft-07 object describing credentialSubject fields.
 */

export interface SchemaField {
  name: string;
  type: string;
  format?: string;
  required: boolean;
  label: string;
}

export interface CredentialSchema {
  id: string;
  title: string;
  fields: SchemaField[];
}

// ---------------------------------------------------------------------------
// Raw JSON Schemas (same as packages/schema-engine/src/schemas/index.ts)
// ---------------------------------------------------------------------------

const educationSchema = {
  title: "Education Credential",
  required: ["name", "degree", "institution", "dateConferred"],
  properties: {
    name: { type: "string" },
    degree: { type: "string" },
    institution: { type: "string" },
    dateConferred: { type: "string", format: "date" },
  },
} as const;

const employmentSchema = {
  title: "Employment Credential",
  required: ["name", "employer", "position", "startDate"],
  properties: {
    name: { type: "string" },
    employer: { type: "string" },
    position: { type: "string" },
    startDate: { type: "string", format: "date" },
  },
} as const;

const identitySchema = {
  title: "Identity Credential",
  required: ["name", "dateOfBirth", "nationality", "documentNumber"],
  properties: {
    name: { type: "string" },
    dateOfBirth: { type: "string", format: "date" },
    nationality: { type: "string" },
    documentNumber: { type: "string" },
  },
} as const;

const healthSchema = {
  title: "Health Credential",
  required: ["name", "certification", "issuingBody", "validUntil"],
  properties: {
    name: { type: "string" },
    certification: { type: "string" },
    issuingBody: { type: "string" },
    validUntil: { type: "string", format: "date" },
  },
} as const;

const businessSchema = {
  title: "Business Credential",
  required: ["name", "registrationNumber", "jurisdiction", "incorporationDate"],
  properties: {
    name: { type: "string" },
    registrationNumber: { type: "string" },
    jurisdiction: { type: "string" },
    incorporationDate: { type: "string", format: "date" },
  },
} as const;

// ---------------------------------------------------------------------------
// Derive structured SchemaField arrays from the raw schemas
// ---------------------------------------------------------------------------

function toLabel(fieldName: string): string {
  return fieldName
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (c) => c.toUpperCase())
    .trim();
}

function deriveFields(raw: {
  required: readonly string[];
  properties: Record<string, { type: string; format?: string }>;
}): SchemaField[] {
  return Object.entries(raw.properties).map(([name, prop]) => ({
    name,
    type: prop.type,
    format: prop.format,
    required: (raw.required as readonly string[]).includes(name),
    label: toLabel(name),
  }));
}

export const SCHEMAS: CredentialSchema[] = [
  { id: "education", title: educationSchema.title, fields: deriveFields(educationSchema) },
  { id: "employment", title: employmentSchema.title, fields: deriveFields(employmentSchema) },
  { id: "identity", title: identitySchema.title, fields: deriveFields(identitySchema) },
  { id: "health", title: healthSchema.title, fields: deriveFields(healthSchema) },
  { id: "business", title: businessSchema.title, fields: deriveFields(businessSchema) },
];

export function getSchema(id: string): CredentialSchema | undefined {
  return SCHEMAS.find((s) => s.id === id);
}
