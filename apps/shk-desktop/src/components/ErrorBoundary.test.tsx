// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
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
});
