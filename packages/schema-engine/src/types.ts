export interface SchemaDefinition {
  id: string;
  schema: Record<string, unknown>;
  contextUrl?: string;
  /** Semver version string for this schema (e.g. "1.0.0"). */
  version: string;
  /** ISO 8601 timestamp of when this schema was last updated. */
  lastUpdated: string;
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

/** Result of checking for schema updates against a remote manifest. */
export interface SchemaUpdateResult {
  /** Whether any updates are available. */
  hasUpdates: boolean;
  /** Schema IDs that have newer versions available. */
  updatedIds: string[];
  /** The remote manifest that was fetched. */
  remoteManifest: SchemaManifest;
}
