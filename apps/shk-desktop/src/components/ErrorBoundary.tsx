import { AlertTriangle } from "lucide-react";
import React from "react";
import { Button } from "./Button";

type Props = {
  title: string;
  description: string;
  reloadLabel: string;
  /**
   * `screen` (default) replaces the whole window and reloads the app.
   * `panel` replaces only its children and re-renders them on retry, so one
   * failing section does not take the rest of the view down with it.
   */
  variant?: "screen" | "panel";
  children: React.ReactNode;
};

type State = {
  error: Error | null;
};

export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("render error:", error, info.componentStack);
  }

  private reload = () => {
    window.location.reload();
  };

  private retry = () => {
    this.setState({ error: null });
  };

  render() {
    if (this.state.error && this.props.variant === "panel") {
      return (
        <section
          role="alert"
          className="flex flex-col gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 sm:flex-row sm:items-start sm:justify-between"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle size={16} aria-hidden="true" className="mt-0.5 shrink-0 text-red-300" />
            <div>
              <h3 className="text-sm font-semibold text-red-50">{this.props.title}</h3>
              <p className="mt-1 text-[12px] leading-relaxed text-red-100/90">
                {this.props.description}
              </p>
            </div>
          </div>
          <Button variant="secondary" size="sm" className="shrink-0" onClick={this.retry}>
            {this.props.reloadLabel}
          </Button>
        </section>
      );
    }

    if (this.state.error) {
      return (
        <div className="grid h-screen w-screen place-items-center bg-surface px-6 text-text">
          <section
            role="alert"
            className="w-full max-w-lg rounded-2xl border border-red-500/30 bg-red-500/10 p-6 shadow-2xl shadow-black/40"
          >
            <div className="flex items-start gap-3">
              <AlertTriangle
                size={20}
                aria-hidden="true"
                className="mt-0.5 shrink-0 text-red-300"
              />
              <div>
                <h1 className="text-base font-semibold text-red-50">{this.props.title}</h1>
                <p className="mt-2 text-sm leading-relaxed text-red-100/90">
                  {this.props.description}
                </p>
              </div>
            </div>
            <div className="mt-5 flex justify-end">
              <Button variant="primary" size="sm" onClick={this.reload}>
                {this.props.reloadLabel}
              </Button>
            </div>
          </section>
        </div>
      );
    }

    return this.props.children;
  }
}
