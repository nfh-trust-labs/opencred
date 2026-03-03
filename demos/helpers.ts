const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";

export function header(title: string): void {
  const line = "=".repeat(60);
  console.log(`\n${MAGENTA}${BOLD}${line}${RESET}`);
  console.log(`${MAGENTA}${BOLD}  ${title}${RESET}`);
  console.log(`${MAGENTA}${BOLD}${line}${RESET}\n`);
}

export function success(msg: string): void {
  console.log(`${GREEN}  [PASS]${RESET} ${msg}`);
}

export function info(msg: string): void {
  console.log(`${CYAN}  [INFO]${RESET} ${msg}`);
}

export function warn(msg: string): void {
  console.log(`${YELLOW}  [WARN]${RESET} ${msg}`);
}

export function error(msg: string): void {
  console.log(`${RED}  [FAIL]${RESET} ${msg}`);
}

export function json(label: string, obj: unknown): void {
  console.log(`${DIM}  ${label}:${RESET}`);
  const lines = JSON.stringify(obj, null, 2).split("\n");
  for (const line of lines) {
    console.log(`${DIM}    ${line}${RESET}`);
  }
}

export function separator(): void {
  console.log(`\n${DIM}${"─".repeat(60)}${RESET}\n`);
}

export function step(num: number, label: string): void {
  console.log(`${BOLD}  Step ${num}: ${label}${RESET}`);
}
