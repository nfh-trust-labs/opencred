export interface SchemaDefinition {
  id: string;
  schema: Record<string, unknown>;
  contextUrl?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationFieldError[];
}

export interface ValidationFieldError {
  field: string;
  message: string;
}
