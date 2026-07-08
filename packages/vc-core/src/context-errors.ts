import { OpenCredError } from "@opencred/shared";

export class ContextNotFoundError extends OpenCredError {
  public readonly contextUrl: string;
  constructor(url: string) {
    super(
      `JSON-LD context not found: ${url}. The context is not bundled and not in the local context store. Import the context or use VC-JWT proof format.`,
      "CONTEXT_NOT_FOUND",
      422,
    );
    this.contextUrl = url;
    this.name = "ContextNotFoundError";
  }
}
