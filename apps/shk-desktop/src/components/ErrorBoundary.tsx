import { AlertTriangle } from "lucide-react";
import React from "react";
import { Button } from "./Button";

type Props = {
  title: string;
  description: string;
  reloadLabel: string;
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

  render() {
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
