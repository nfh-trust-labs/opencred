/**
 * Docker helpers for the matrix harness.
 *
 * Each matrix algorithm gets its own short-lived container running the
 * OpenCred server image with a freshly generated software key mounted
 * read-only. The image tag comes from OPENCRED_E2E_IMAGE; the suite skips
 * (with a visible reason) when it's unset or the docker daemon is down —
 * silence must never read as coverage.
 */
import { execFileSync, execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const E2E_IMAGE = process.env.OPENCRED_E2E_IMAGE;
export const API_KEY = "e2e-matrix-api-key-0123456789abcdef";

export type MatrixAlgorithm = "P-256" | "P-384" | "Ed25519" | "RSA-2048";

export function dockerAvailable(): boolean {
  try {
    execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/** Generate a PKCS#8 PEM signing key for the given matrix algorithm. */
export function generateKeyPem(algorithm: MatrixAlgorithm): string {
  const keyPair =
    algorithm === "Ed25519"
      ? generateKeyPairSync("ed25519")
      : algorithm === "RSA-2048"
        ? generateKeyPairSync("rsa", { modulusLength: 2048 })
        : generateKeyPairSync("ec", {
            namedCurve: algorithm === "P-384" ? "secp384r1" : "prime256v1",
          });
  return keyPair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
}

export interface ServerContainer {
  baseUrl: string;
  name: string;
  stop: () => void;
  logs: () => string;
}

/**
 * Start a server container with the given key and wait for /v1/health to
 * report ready. Extra env vars (e.g. DeDi config) are passed through.
 */
export async function startServer(
  algorithm: MatrixAlgorithm,
  port: number,
  extraEnv: Record<string, string> = {},
): Promise<ServerContainer> {
  const dir = mkdtempSync(join(tmpdir(), "opencred-e2e-"));
  const keyPath = join(dir, "signing-key.pem");
  writeFileSync(keyPath, generateKeyPem(algorithm));
  // The container runs as the non-root `node` user; the bind-mounted key
  // must be world-readable for it.
  chmodSync(keyPath, 0o644);

  const name = `opencred-e2e-${algorithm.toLowerCase().replace(/[^a-z0-9]/g, "")}-${port}`;
  const args = [
    "run",
    "-d",
    "--rm",
    "--name",
    name,
    "-p",
    `${port}:3100`,
    "-v",
    `${keyPath}:/keys/signing-key.pem:ro`,
    "-e",
    "OPENCRED_KEY_PATH=/keys/signing-key.pem",
    "-e",
    `OPENCRED_API_KEY=${API_KEY}`,
  ];
  for (const [k, v] of Object.entries(extraEnv)) {
    args.push("-e", `${k}=${v}`);
  }
  args.push(E2E_IMAGE!);
  execFileSync("docker", args, { stdio: "pipe" });

  const baseUrl = `http://localhost:${port}`;
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      const res = await fetch(`${baseUrl}/v1/health`);
      if (res.ok) {
        const body = (await res.json()) as { ready?: boolean };
        if (body.ready) break;
      }
    } catch {
      // Container still booting.
    }
    if (Date.now() > deadline) {
      let logs = "";
      try {
        logs = execFileSync("docker", ["logs", name], { stdio: "pipe" }).toString();
      } catch {
        // Container may have already exited.
      }
      try {
        execFile("docker", ["rm", "-f", name]);
      } catch {
        // Best-effort cleanup.
      }
      throw new Error(`Server container ${name} did not become ready in 60s.\n${logs}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }

  return {
    baseUrl,
    name,
    stop: () => {
      try {
        execFileSync("docker", ["rm", "-f", name], { stdio: "pipe" });
      } catch {
        // Already gone.
      }
    },
    logs: () => {
      try {
        return execFileSync("docker", ["logs", name], { stdio: "pipe" }).toString();
      } catch {
        return "";
      }
    },
  };
}
