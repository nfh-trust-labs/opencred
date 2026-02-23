import pino from "pino";
import type { EnvConfig } from "@opencred/shared";

export type Logger = pino.Logger;

export function createLogger(config: EnvConfig): Logger {
  return pino({
    level: config.LOG_LEVEL,
    ...(config.NODE_ENV === "development" && {
      transport: {
        target: "pino/file",
        options: { destination: 1 },
      },
    }),
    serializers: {
      req(req) {
        return {
          method: req.method,
          url: req.url,
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
    redact: {
      paths: [
        "req.headers.authorization",
        "req.headers.cookie",
        "*.privateKey",
        "*.signingKey",
        "*.secret",
        "*.password",
        "*.token",
        "*.credential",
      ],
      censor: "[REDACTED]",
    },
  });
}
