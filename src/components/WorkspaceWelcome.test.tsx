import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../services/api", () => ({
  api: {
    workspaceState: vi.fn(),
    getPreferences: vi.fn(),
    savePreferences: vi.fn(),
    clearWorkspace: vi.fn(),
  },
}));
vi.mock("../lib/dialog", () => ({
  pickFile: vi.fn(),
  pickSavePath: vi.fn(),
}));

import { WorkspaceGate } from "./WorkspaceWelcome";
import { api } from "../services/api";
import { pickSavePath } from "../lib/dialog";
import { WorkspaceProvider } from "../context/WorkspaceContext";

const state = {
  hasData: true,
  datasets: 1,
  events: 10,
  captures: 1,
  packets: 42,
  flows: 4,
  alerts: 2,
  investigations: 1,
};

function renderGate() {
  return render(
    <WorkspaceProvider>
      <WorkspaceGate>
        <div>app body</div>
      </WorkspaceGate>
    </WorkspaceProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.workspaceState).mockResolvedValue(state);
  vi.mocked(api.getPreferences).mockResolvedValue({ startupBehavior: "ask" });
  vi.mocked(api.savePreferences).mockResolvedValue({ startupBehavior: "resume" });
  vi.mocked(api.clearWorkspace).mockResolvedValue({
    datasets: 1,
    events: 10,
    captures: 1,
    packets: 42,
    flows: 4,
    alerts: 2,
    investigations: 1,
    backupPath: "/tmp/backup.db",
  });
  vi.mocked(pickSavePath).mockResolvedValue("/tmp/backup.db");
});

describe("WorkspaceGate", () => {
  it("skips the welcome modal when the workspace is empty", async () => {
    vi.mocked(api.workspaceState).mockResolvedValue({ ...state, hasData: false });
    renderGate();

    await waitFor(() => expect(vi.mocked(api.workspaceState)).toHaveBeenCalled());
    expect(screen.queryByTestId("workspace-welcome")).not.toBeInTheDocument();
    expect(screen.getByText("app body")).toBeInTheDocument();
  });

  it("skips the welcome modal when the preference is resume", async () => {
    vi.mocked(api.getPreferences).mockResolvedValue({ startupBehavior: "resume" });
    renderGate();

    await waitFor(() => expect(vi.mocked(api.getPreferences)).toHaveBeenCalled());
    expect(screen.queryByTestId("workspace-welcome")).not.toBeInTheDocument();
  });

  it("welcome modal resumes and can persist the automatic preference", async () => {
    const user = userEvent.setup();
    renderGate();

    expect(await screen.findByText("Welcome back to NULLPLINTH.")).toBeInTheDocument();
    await user.click(screen.getByLabelText("Do not ask again, resume automatically"));
    await user.click(screen.getByRole("button", { name: "Resume" }));

    expect(vi.mocked(api.savePreferences)).toHaveBeenCalledWith({ startupBehavior: "resume" });
    expect(screen.queryByTestId("workspace-welcome")).not.toBeInTheDocument();
  });

  it("start fresh asks for confirmation, backs up and reports the cleared workspace", async () => {
    const user = userEvent.setup();
    renderGate();

    await screen.findByText("Welcome back to NULLPLINTH.");
    await user.click(screen.getByRole("button", { name: "Start Fresh" }));

    expect(await screen.findByText("Start a fresh workspace?")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear workspace" }));

    expect(vi.mocked(pickSavePath)).toHaveBeenCalled();
    expect(vi.mocked(api.clearWorkspace)).toHaveBeenCalledWith("/tmp/backup.db");
    expect(await screen.findByText("Workspace cleared")).toBeInTheDocument();
    expect(screen.getByText(/removed 1 dataset and 10 events/)).toBeInTheDocument();
  });

  it("does not clear the workspace when the backup dialog is cancelled", async () => {
    const user = userEvent.setup();
    vi.mocked(pickSavePath).mockResolvedValue(null);
    renderGate();

    await screen.findByText("Welcome back to NULLPLINTH.");
    await user.click(screen.getByRole("button", { name: "Start Fresh" }));
    await user.click(screen.getByRole("button", { name: "Clear workspace" }));

    expect(vi.mocked(api.clearWorkspace)).not.toHaveBeenCalled();
    expect(await screen.findByText(/Backup cancelled, so the workspace was not cleared/)).toBeInTheDocument();
    expect(screen.getByText("Start a fresh workspace?")).toBeInTheDocument();
  });
});
