import { render } from "@testing-library/react";
import type { ReactElement } from "react";

import { ModeProvider } from "../context/ModeContext";

export function renderWithMode(ui: ReactElement) {
  return render(<ModeProvider>{ui}</ModeProvider>);
}
