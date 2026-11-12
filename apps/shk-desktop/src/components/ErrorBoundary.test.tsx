// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "./ErrorBoundary";

function BrokenChild(): never {
  throw new Error("boom");
}

describe("ErrorBoundary", () => {
  it("renders fallback UI when a child throws", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <ErrorBoundary title="Crash" description="Try again" reloadLabel="Reload">
        <BrokenChild />
      </ErrorBoundary>,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("Crash");
    expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();
    errorSpy.mockRestore();
  });

  it("contains a failing panel and retries it in place", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    let broken = true;
    function Panel() {
      if (broken) throw new Error("boom");
      return <p>panel content</p>;
    }

    render(
      <>
        <p>sibling</p>
        <ErrorBoundary variant="panel" title="Crash" description="Panel failed" reloadLabel="Retry">
          <Panel />
        </ErrorBoundary>
      </>,
    );

    expect(screen.getByText("sibling")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Panel failed");
    expect(screen.getByRole("alert")).not.toHaveClass("h-screen");

    broken = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(screen.getByText("panel content")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    errorSpy.mockRestore();
  });
});
