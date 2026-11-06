import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ModeProvider } from "../context/ModeContext";
import { AppShell } from "./AppShell";

function renderShell(section: "overview" | "network" = "overview", onSelect = vi.fn()) {
  render(
    <ModeProvider>
      <AppShell section={section} onSelect={onSelect}>
        <div>content</div>
      </AppShell>
    </ModeProvider>,
  );
  return { onSelect };
}

describe("AppShell shortcuts and layout", () => {
  it("jumps to a section with Alt plus its number", () => {
    const { onSelect } = renderShell();
    fireEvent.keyDown(window, { key: "3", altKey: true });
    expect(onSelect).toHaveBeenCalledWith("network");
  });

  it("ignores number keys without Alt", () => {
    const { onSelect } = renderShell();
    fireEvent.keyDown(window, { key: "3" });
    expect(onSelect).not.toHaveBeenCalled();
  });

  it("toggles experience mode with Alt+M", () => {
    renderShell();
    const before = screen.getByRole("button", { name: "Analyst" }).getAttribute("aria-pressed");
    fireEvent.keyDown(window, { key: "m", altKey: true });
    const after = screen.getByRole("button", { name: "Analyst" }).getAttribute("aria-pressed");
    expect(after).not.toBe(before);
  });

  it("exposes a fullscreen control labelled with its shortcut", () => {
    renderShell();
    expect(screen.getByRole("button", { name: /fullscreen/i })).toBeInTheDocument();
  });
});
