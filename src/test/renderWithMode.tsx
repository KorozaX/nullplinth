import { render } from "@testing-library/react";
import type { ReactElement } from "react";

import { ModeProvider } from "../context/ModeContext";
import { WorkspaceProvider } from "../context/WorkspaceContext";
import { ImportProvider } from "../components/ImportWorkflow";

export function renderWithMode(ui: ReactElement) {
  return render(
    <WorkspaceProvider>
      <ModeProvider>
        <ImportProvider>{ui}</ImportProvider>
      </ModeProvider>
    </WorkspaceProvider>,
  );
}
