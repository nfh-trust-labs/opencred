import { z } from "zod";

export const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),

  // DeDi integration
  DEDI_API_URL: z.string().url().optional(),
  DEDI_API_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  DEDI_AUTH_TYPE: z.enum(["bearer", "api-key"]).default("api-key"),
  DEDI_API_KEY: z.string().optional(),
  DEDI_EMAIL: z.string().email().optional(),
  DEDI_PASSWORD: z.string().optional(),
  DEDI_DEFAULT_NAMESPACE: z.string().optional(),

  // Session / state
  SESSION_TTL_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(4 * 60 * 60 * 1000), // 4 hours
  SESSION_SWEEP_INTERVAL_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(60 * 1000), // 60 seconds

  // Auth / JWT
  JWT_SECRET: z.string().min(32).optional(),
  JWT_ISSUER: z.string().default("opencred"),
  JWT_EXPIRY_SECONDS: z.coerce.number().int().positive().default(3600),

  // Batch processing
  MAX_BATCH_SIZE: z.coerce.number().int().positive().default(1000),

  // CSCA Trust Store
  CSCA_TRUST_STORE_PATH: z.string().optional(),

  // CORS
  CORS_ORIGIN: z.string().default("http://localhost:5173"),
}).superRefine((data, ctx) => {
  if (data.DEDI_API_URL) {
    if (data.DEDI_AUTH_TYPE === "api-key" && !data.DEDI_API_KEY) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "DEDI_API_KEY is required when DEDI_AUTH_TYPE is 'api-key'",
        path: ["DEDI_API_KEY"],
      });
    }
    if (data.DEDI_AUTH_TYPE === "bearer") {
      if (!data.DEDI_EMAIL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DEDI_EMAIL is required when DEDI_AUTH_TYPE is 'bearer'",
          path: ["DEDI_EMAIL"],
        });
      }
      if (!data.DEDI_PASSWORD) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "DEDI_PASSWORD is required when DEDI_AUTH_TYPE is 'bearer'",
          path: ["DEDI_PASSWORD"],
        });
      }
    }
  }
});

export type EnvConfig = z.infer<typeof envSchema>;

export function loadConfig(env: Record<string, string | undefined> = process.env): EnvConfig {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => `  ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    throw new Error(`Invalid environment configuration:\n${formatted}`);
  }
  return result.data;
}
