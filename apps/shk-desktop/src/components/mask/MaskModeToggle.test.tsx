// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../../i18n";
import { en } from "../../i18n/messages/en";
import { MaskModeToggle } from "./MaskModeToggle";

describe("MaskModeToggle", () => {
  beforeEach(() => {
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("renders both methods as radios and reports a change", () => {
    const onChange = vi.fn();
    render(
      <I18nProvider>
        <MaskModeToggle mode="redact" onChange={onChange} messages={en.mask.mode} />
      </I18nProvider>,
    );

    const redact = screen.getByRole("radio", { name: /Redact/ });
    const pseudonymize = screen.getByRole("radio", { name: /Pseudonymize/ });
    expect(redact).toBeChecked();
    expect(pseudonymize).not.toBeChecked();

    fireEvent.click(pseudonymize);
    expect(onChange).toHaveBeenCalledWith("pseudonymize");
  });

  it("disables the group while a run is in progress", () => {
    render(
      <I18nProvider>
        <MaskModeToggle mode="pseudonymize" onChange={vi.fn()} disabled messages={en.mask.mode} />
      </I18nProvider>,
    );
    expect(screen.getByRole("radio", { name: /Redact/ })).toBeDisabled();
    expect(screen.getByRole("radio", { name: /Pseudonymize/ })).toBeChecked();
  });
});
