export interface SchemaSource {
  /** Whether this credential's schema is authored in opencred-vc-schemas (defined) or fetched from an upstream third-party URL (referenced). */
  kind: "defined" | "referenced";
  /** The fully-qualified URL the schema was fetched from at build time. */
  upstreamUrl: string;
  /** Human-readable owner of the upstream source (e.g. "OpenCred", "W3C CCG", "1EdTech", "DIF"). */
  upstreamOwner: string;
  /** SPDX license identifier for the upstream source. */
  upstreamLicense: string;
}

export type SchemaCategory =
  | "education"
  | "employment"
  | "identity"
  | "health"
  | "business"
  | "utility"
  | "supply-chain"
  | "other";

export interface SchemaDefinition {
  id: string;
  schema: Record<string, unknown>;
  contextUrl?: string;
  /** Semver version string for this schema (e.g. "1.0.0"). */
  version: string;
  /** ISO 8601 timestamp of when this schema was last updated. */
  lastUpdated: string;
  /** Canonical SHA-256 of the schema (lowercase hex). Required: every bundled schema is hash-pinned. */
  checksum: string;
  /** Provenance metadata: where the schema came from, who owns it, and under what license. */
  source: SchemaSource;
  /** Optional category for UI grouping. */
  category?: SchemaCategory;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationFieldError[];
}

export interface ValidationFieldError {
  field: string;
  message: string;
}

/** Entry in a schema manifest describing a single schema's version and integrity. */
export interface SchemaManifestEntry {
  id: string;
  version: string;
  checksum: string;
}

/** Manifest listing all available schemas with their versions and checksums. */
export interface SchemaManifest {
  schemas: SchemaManifestEntry[];
}
