export interface DeDiLogger {
  debug(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
}

export const noopLogger: DeDiLogger = {
  debug() {},
  warn() {},
  error() {},
};
