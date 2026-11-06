import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../services/api", () => ({
  api: {
    listInvestigations: vi.fn(),
    getInvestigation: vi.fn(),
    createInvestigation: vi.fn(),
    updateInvestigation: vi.fn(),
    addInvestigationNote: vi.fn(),
    getAlert: vi.fn(),
    getEvent: vi.fn(),
    exportInvestigation: vi.fn(),
  },
}));

import { InvestigationsScreen } from "./InvestigationsScreen";
import { api } from "../services/api";
import { demoInvestigation } from "../test/fixtures";
import { renderWithMode } from "../test/renderWithMode";

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  vi.mocked(api.listInvestigations).mockResolvedValue([demoInvestigation]);
  vi.mocked(api.getInvestigation).mockResolvedValue({
    investigation: demoInvestigation,
    notes: [],
    alerts: [],
  });
  vi.mocked(api.addInvestigationNote).mockResolvedValue({
    investigation: { ...demoInvestigation, noteCount: 1 },
    notes: [
      {
        id: 1,
        investigationId: demoInvestigation.id,
        body: "Imported host isolated.",
        createdAt: 1767225900000,
      },
    ],
    alerts: [],
  });
});

describe("InvestigationsScreen", () => {
  it("opens a case and adds a note", async () => {
    const user = userEvent.setup();
    renderWithMode(<InvestigationsScreen focusId={null} />);

    await user.click(await screen.findByRole("button", { name: /Suspicious outbound traffic/ }));

    const noteInput = await screen.findByLabelText("Add note");
    await user.type(noteInput, "Imported host isolated.");
    await user.click(screen.getByRole("button", { name: "Add note" }));

    expect(vi.mocked(api.addInvestigationNote)).toHaveBeenCalledWith(demoInvestigation.id, "Imported host isolated.");
    expect(await screen.findByText("Imported host isolated.")).toBeInTheDocument();
  });

  it("renders an empty state when no cases exist", async () => {
    vi.mocked(api.listInvestigations).mockResolvedValue([]);
    renderWithMode(<InvestigationsScreen focusId={null} />);

    expect(await screen.findByText("No investigations yet")).toBeInTheDocument();
  });
});
