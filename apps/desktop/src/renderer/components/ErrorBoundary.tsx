/**
 * ErrorBoundary — catches unhandled React render errors.
 *
 * Displays a fallback UI with the error message and options to reload
 * the app or copy the error for a bug report.
 */

import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  copied: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, copied: false };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: { componentStack?: string | null }): void {
    // Log to console — electron-log's renderer integration picks this up
    console.error("[ErrorBoundary] Render error:", error.message, info.componentStack);
  }

  handleReload = (): void => {
    window.location.reload();
  };

  handleCopy = async (): Promise<void> => {
    const { error } = this.state;
    if (!error) return;
    const text = `Error: ${error.message}\n\nStack:\n${error.stack ?? "N/A"}`;
    try {
      await navigator.clipboard.writeText(text);
      this.setState({ copied: true });
      setTimeout(() => this.setState({ copied: false }), 2000);
    } catch {
      // Clipboard API may fail in some contexts
    }
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    const { error, copied } = this.state;

    return (
      <div className="min-h-screen bg-surface-bg flex items-center justify-center p-8 font-body">
        <div className="max-w-lg w-full bg-white rounded-lg shadow-md border border-border-default p-6 space-y-4">
          <h1 className="text-heading-md font-heading text-txt-primary">
            Something went wrong
          </h1>
          <p className="text-body-sm text-txt-secondary">
            An unexpected error occurred in the application. You can try reloading
            or copy the error details for a bug report.
          </p>
          {error && (
            <pre className="text-xs text-red-700 bg-red-50 border border-red-200 rounded p-3 overflow-auto max-h-40 whitespace-pre-wrap">
              {error.message}
            </pre>
          )}
          <div className="flex gap-3">
            <button
              onClick={this.handleReload}
              className="px-4 py-2 text-sm font-medium text-white bg-brand-blue rounded hover:bg-brand-blue/90 transition-colors"
            >
              Reload App
            </button>
            <button
              onClick={() => void this.handleCopy()}
              className="px-4 py-2 text-sm font-medium text-txt-primary bg-surface-card border border-border-default rounded hover:bg-gray-100 transition-colors"
            >
              {copied ? "Copied!" : "Copy Error"}
            </button>
          </div>
        </div>
      </div>
    );
  }
}
