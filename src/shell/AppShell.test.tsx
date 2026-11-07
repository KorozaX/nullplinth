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

  it("routes the global search query to the event explorer", () => {
    const onSelect = vi.fn();
    const onSearch = vi.fn();
    render(
      <ModeProvider>
        <AppShell section="overview" onSelect={onSelect} onSearch={onSearch}>
          <div>content</div>
        </AppShell>
      </ModeProvider>,
    );
    const input = screen.getByLabelText("Global search");
    fireEvent.change(input, { target: { value: " failed login " } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onSearch).toHaveBeenCalledWith("failed login");
  });
});
