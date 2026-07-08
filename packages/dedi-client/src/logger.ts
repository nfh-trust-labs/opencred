export interface DeDiLogger {
  info(msg: string, ...args: unknown[]): void;
  debug(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
}

export const noopLogger: DeDiLogger = {
  info() {},
  debug() {},
  warn() {},
  error() {},
};
